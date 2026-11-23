package imagedb

// Live tests against the frozen imagedb-server binaries, started by run_tests.sh (IMDB_LIVE=1 and the servers'
// addresses in the environment). Without IMDB_LIVE they are skipped; with it, a missing server fails them.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"imagedb.dev/imagedb/wire"
)

func live(t *testing.T) {
	t.Helper()
	if os.Getenv("IMDB_LIVE") != "1" {
		t.Skip("live: run_tests.sh starts the servers (IMDB_LIVE=1)")
	}
}

func env(t *testing.T, k string) string {
	t.Helper()
	v := os.Getenv(k)
	if v == "" {
		t.Fatalf("live: %s not set (run_tests.sh sets it)", k)
	}
	return v
}

func envPin(t *testing.T, k string) []byte {
	p, err := ParsePin(env(t, k))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// server A: the default (exporter) server; B: --channel-binding any; C: A's certificate on 127.0.0.2
func cfgSock(t *testing.T, s string) Config {
	return Config{Socket: env(t, "IMDB_"+s+"_SOCK"), User: env(t, "IMDB_USER"), Password: env(t, "IMDB_PASSWORD")}
}

func cfgCA(t *testing.T, s string) Config {
	return Config{Addr: env(t, "IMDB_"+s+"_ADDR"), CAFile: env(t, "IMDB_"+s+"_CA"), User: env(t, "IMDB_USER"),
		Password: env(t, "IMDB_PASSWORD")}
}

func cfgPin(t *testing.T, s string) Config {
	return Config{Addr: env(t, "IMDB_"+s+"_ADDR"), Pin: envPin(t, "IMDB_"+s+"_PIN"), User: env(t, "IMDB_USER"),
		Password: env(t, "IMDB_PASSWORD")}
}

func dial(t *testing.T, cfg Config) *Conn {
	t.Helper()
	c, err := Connect(context.Background(), cfg)
	if err != nil {
		t.Fatalf("connect %s%s: %v", cfg.Socket, cfg.Addr, err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func mustExec(t *testing.T, c *Conn, sql string, args ...any) *Done {
	t.Helper()
	d, err := c.Exec(context.Background(), sql, args...)
	if err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return d
}

func one(t *testing.T, c *Conn, sql string, args ...any) []any {
	t.Helper()
	res, err := c.Batch(context.Background(), Statement{SQL: sql, Args: args})
	if err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	if len(res) != 1 || len(res[0].Rows) != 1 {
		t.Fatalf("%s: %d results", sql, len(res))
	}
	return res[0].Rows[0]
}

func TestLiveLogin(t *testing.T) {
	live(t)
	for name, cfg := range map[string]Config{
		"A socket": cfgSock(t, "A"), "A TCP by CA": cfgCA(t, "A"), "A TCP by pin": cfgPin(t, "A"),
		"B socket": cfgSock(t, "B"), "B TCP by CA": cfgCA(t, "B"), "B TCP by pin": cfgPin(t, "B"),
	} {
		c := dial(t, cfg)
		if got := one(t, c, "SELECT 1 + 1 AS two")[0]; got != int64(2) {
			t.Fatalf("%s: %v", name, got)
		}
		if err := c.Ping(context.Background()); err != nil {
			t.Fatalf("%s: ping: %v", name, err)
		}
		if c.tc != nil {
			cs := c.tc.ConnectionState()
			if cs.Version != 0x0304 || cs.NegotiatedProtocol != "imdbwir1" {
				t.Fatalf("%s: TLS %x %q", name, cs.Version, cs.NegotiatedProtocol)
			}
		}
	}
	// by name: localhost is in the certificate's subjectAltName (DNS:localhost)
	cfg := cfgCA(t, "A")
	_, port, _ := strings.Cut(cfg.Addr, ":")
	cfg.Addr = "localhost:" + port
	dial(t, cfg)
}

// TestLiveBinding: §8f both ways. A default server takes the exporter and refuses tls-server-end-point (verdict 2, no
// retry with another type); a server run with --channel-binding any takes both.
func TestLiveBinding(t *testing.T) {
	live(t)
	for _, s := range []string{"A", "B"} {
		for _, b := range []Binding{BindingExporter, BindingEndpoint} {
			for _, mk := range []func(*testing.T, string) Config{cfgCA, cfgPin} {
				cfg := mk(t, s)
				cfg.Binding = b
				c, err := Connect(context.Background(), cfg)
				refused := s == "A" && b == BindingEndpoint
				if refused {
					var e *Error
					if !errors.As(err, &e) || e.Code != CodeAuth || !strings.Contains(e.Message, "channel binding type") {
						t.Fatalf("%s, binding %d: %v, want verdict 2", s, b, err)
					}
					continue
				}
				if err != nil {
					t.Fatalf("%s, binding %d: %v", s, b, err)
				}
				one(t, c, "SELECT 1")
				c.Close()
			}
		}
	}
}

// TestLivePin: the pin is the key's SPKI SHA-256 (as `cert` printed it), never the certificate's hash, so it survives
// `cert --renew`: run_tests.sh renewed A's certificate (same key, same CA) before starting A.
func TestLivePin(t *testing.T) {
	live(t)
	pin := envPin(t, "IMDB_A_PIN")
	renewed, err := os.ReadFile(env(t, "IMDB_A_CRT"))
	if err != nil {
		t.Fatal(err)
	}
	old, err := os.ReadFile(env(t, "IMDB_A_CRT_OLD")) // the certificate before the renewal, kept under its serial
	if err != nil {
		t.Fatal(err)
	}
	pr, _ := PinOf(renewed)
	po, _ := PinOf(old)
	if !bytes.Equal(pr, pin) || !bytes.Equal(po, pin) {
		t.Fatal("the pin is not the key's SPKI SHA-256 of both certificates")
	}
	der := func(p []byte) []byte { b, _ := pem.Decode(p); return b.Bytes }
	if bytes.Equal(der(renewed), der(old)) {
		t.Fatal("the renewal kept the certificate")
	}
	if h := sha256.Sum256(der(renewed)); bytes.Equal(h[:], pin) {
		t.Fatal("the pin is the certificate's hash")
	}
	c := dial(t, cfgPin(t, "A"))
	if got := c.tc.ConnectionState().PeerCertificates[0].Raw; !bytes.Equal(got, der(renewed)) {
		t.Fatal("the server does not present the renewed certificate")
	}
}

// TestLiveRefused: no verification can be skipped and no wrong one passes.
func TestLiveRefused(t *testing.T) {
	live(t)
	expect := func(name string, cfg Config, code int, words string) {
		t.Helper()
		_, err := Connect(context.Background(), cfg)
		var e *Error
		if !errors.As(err, &e) || e.Code != code || !strings.Contains(err.Error(), words) {
			t.Fatalf("%s: %v, want code %d (%s)", name, err, code, words)
		}
	}
	cfg := cfgPin(t, "A")
	cfg.Pin = bytes.Clone(cfg.Pin)
	cfg.Pin[31] ^= 1
	expect("a wrong pin", cfg, CodeAuth, "not the pinned one")
	cfg = cfgPin(t, "A")
	cfg.Pin = envPin(t, "IMDB_X_PIN")
	expect("another server's pin", cfg, CodeAuth, "not the pinned one")
	cfg = cfgCA(t, "A")
	cfg.CAFile = env(t, "IMDB_X_CA")
	expect("another CA", cfg, CodeAuth, "certificate signed by unknown authority")
	expect("A's certificate on 127.0.0.2 by its CA", cfgCA(t, "C"), CodeAuth, "127.0.0.2")
	dial(t, cfgPin(t, "C")) // a pin names the key, not the host (tls.c's rule)
	cfg = cfgSock(t, "A")
	cfg.Password = "not-the-password"
	expect("a wrong password", cfg, CodeAuth, "authentication refused")
	cfg = cfgCA(t, "A")
	cfg.Password = "not-the-password"
	expect("a wrong password over TCP", cfg, CodeAuth, "authentication refused")
	cfg = cfgSock(t, "A")
	cfg.User = "nobody"
	expect("an unknown role", cfg, CodeAuth, "authentication refused")
	cfg = cfgCA(t, "A")
	cfg.CAFile, cfg.Pin = "", nil
	expect("no CA and no pin", cfg, CodeInvalid, "exactly one")
}

func mkEnum(t *testing.T, c *Conn, name string, labels ...string) {
	t.Helper()
	q := make([]string, len(labels))
	for i, l := range labels {
		q[i] = "'" + strings.ReplaceAll(l, "'", "''") + "'"
	}
	mustExec(t, c, fmt.Sprintf("CREATE TYPE %s AS ENUM (%s)", name, strings.Join(q, ", ")))
}

// TestLiveTypes: every type at its edges through a table and back, by parameters (an EXECUTE of several sets) and by a
// SELECT: what comes back is what went in, exactly, and every NULL keeps its column's type.
func TestLiveTypes(t *testing.T) {
	live(t)
	c := dial(t, cfgSock(t, "A"))
	mkEnum(t, c, "tymood", "", "x", "é", "a label of sixty-three bytes, the longest one an ENUM takes....")
	mustExec(t, c, `CREATE TABLE tyall (id BIGINT PRIMARY KEY, s SMALLINT, i INTEGER, f FLOAT64, b BOOL, tx TEXT,
		vc VARCHAR(5), d38 DECIMAL(38,0), d10 DECIMAL(38,10), d2 DECIMAL(10,2), ts TIMESTAMP, tz TIMESTAMPTZ, dt DATE,
		tm TIME, u UUID, ba BYTEA, iv INTERVAL, m tymood)`)
	max38 := new(big.Int).Sub(new(big.Int).Exp(big.NewInt(10), big.NewInt(38), nil), big.NewInt(1))
	d38max, _ := NewDecimal(max38, 0)
	d38min, _ := NewDecimal(new(big.Int).Neg(max38), 0)
	d10max, _ := NewDecimal(max38, 10)
	long := strings.Repeat("ǅ", 32765) + "\U0010FFFF" + "a" // 65,535 bytes of UTF-8: TEXT's edge
	allBytes := make([]byte, 65535)
	for i := range allBytes {
		allBytes[i] = byte(i)
	}
	tzMin := time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC)
	tzMax := time.Date(9999, 12, 31, 23, 59, 59, 999999000, time.UTC)
	rows := [][]any{
		{int64(1), int16(math.MaxInt16), int32(math.MaxInt32), math.MaxFloat64, true, long, "ǅǅǅǅǅ", d38max, d10max,
			MustDecimal("99999999.99"), DateTime{Date{9999, 12, 31}, TimeOfDay{23, 59, 59, 999999}}, tzMax, Date{9999, 12, 31},
			TimeOfDay{23, 59, 59, 999999}, UUID{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff}, allBytes, Interval{math.MaxInt32, math.MaxInt32, math.MaxInt64},
			"a label of sixty-three bytes, the longest one an ENUM takes...."},
		{int64(math.MinInt64), int16(math.MinInt16), int32(math.MinInt32), -math.SmallestNonzeroFloat64, false, "", "",
			d38min, MustDecimal("-0.0000000001"), MustDecimal("-99999999.99"), DateTime{Date{1, 1, 1}, TimeOfDay{}}, tzMin,
			Date{1, 1, 1}, TimeOfDay{}, UUID{}, []byte{}, Interval{math.MinInt32, math.MinInt32, math.MinInt64}, ""},
		{int64(math.MaxInt64), int16(0), int32(0), 0.0, true, "\x01\x7f", "é", DecimalFromInt64(0), MustDecimal("0.0000000000"),
			MustDecimal("0.00"), DateTime{Date{1970, 1, 1}, TimeOfDay{}}, time.Unix(0, 0).UTC(), Date{1970, 1, 1},
			TimeOfDay{12, 0, 0, 1}, UUID{1, 2, 3}, []byte{0}, Interval{1, -2, 3}, "é"},
		{int64(4), NullOf(TypeInt64), (*int32)(nil), sql.NullFloat64{}, (*bool)(nil), sql.NullString{}, NullOf(TypeText),
			sql.Null[Decimal]{}, (*Decimal)(nil), nil, (*DateTime)(nil), sql.NullTime{}, (*Date)(nil), (*TimeOfDay)(nil),
			(*UUID)(nil), []byte(nil), (*Interval)(nil), nil},
	}
	if err := c.Prepare(context.Background(), "tyins", "INSERT INTO tyall VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, "+
		"$11, $12, $13, $14, $15, $16, $17, $18)"); err != nil {
		t.Fatal(err)
	}
	res, err := c.Execute(context.Background(), "tyins", rows...)
	if err != nil || len(res) != len(rows) || res[0].Done.Count != 1 || !res[0].Done.HasWrite {
		t.Fatalf("insert: %v %d", err, len(res))
	}
	r, err := c.Query(context.Background(), "SELECT * FROM tyall ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	cols := r.Columns()
	wantTypes := []Type{TypeInt64, TypeInt64, TypeInt64, TypeFloat64, TypeBool, TypeText, TypeText, TypeDecimal, TypeDecimal,
		TypeDecimal, TypeTimestamp, TypeTimestampTZ, TypeDate, TypeTime, TypeUUID, TypeBytea, TypeInterval, TypeEnum}
	for i, w := range wantTypes {
		if cols[i].Type != w {
			t.Fatalf("column %s: %s, want %s", cols[i].Name, cols[i].Type, w)
		}
	}
	// what the server reports of a result's columns (server/conv.c imdbw_columns_of): a DECIMAL's scale, never its precision
	// (§4: not known), and no INT64 width or VARCHAR length either (§4's table names them: a defect of the note, not the
	// codec), an ENUM's labels in the type's order
	for _, c := range cols {
		if c.Precision != 0 {
			t.Fatalf("column %s: precision %d (the server reports none)", c.Name, c.Precision)
		}
	}
	if cols[8].Scale != 10 || cols[9].Scale != 2 || len(cols[17].Labels) != 4 || cols[17].Labels[2] != "é" {
		t.Fatalf("column shapes: %+v", cols)
	}
	n := 0
	for r.Next() {
		want := rows[[]int{1, 0, 3, 2}[n]]
		got := r.Values()
		raw := r.RawValues()
		for i := range got {
			if !sameValue(t, got[i], want[i]) {
				t.Fatalf("row %d, column %s: %#v, want %#v", n, cols[i].Name, got[i], want[i])
			}
			if raw[i].Null && raw[i].Type != cols[i].Type {
				t.Fatalf("a NULL of %s under a %s column", raw[i].Type, cols[i].Type)
			}
		}
		n++
	}
	if r.Err() != nil || n != 4 || r.Done().Count != 4 || !r.Done().HasRead || r.Done().Read.Commit == 0 {
		t.Fatalf("%d rows, %v, %+v", n, r.Err(), r.Done())
	}
	r.Close()
	// a SUM over INT64 is DECIMAL at scale 0 (a 38-digit total), and two maxima sum past INT64
	mustExec(t, c, "CREATE TABLE tysum (k BIGINT PRIMARY KEY, v BIGINT)")
	mustExec(t, c, "INSERT INTO tysum VALUES (1, $1), (2, $1)", int64(math.MaxInt64))
	res, err = c.Batch(context.Background(), Statement{SQL: "SELECT SUM(v) FROM tysum"})
	if err != nil || res[0].Columns[0].Type != TypeDecimal || res[0].Rows[0][0].(Decimal).String() != "18446744073709551614" {
		t.Fatalf("SUM: %v %+v", err, res)
	}
	// parameters bound as their literals: an INT64 into a DECIMAL column, a label (TEXT) into an ENUM column
	mustExec(t, c, "INSERT INTO tyall (id, d2, m) VALUES (5, $1, $2)", int64(7), "x")
	got := one(t, c, "SELECT d2, m FROM tyall WHERE id = $1", 5)
	if got[0].(Decimal).String() != "7.00" || got[1] != "x" {
		t.Fatalf("literal binding: %v", got)
	}
	// a label the type lacks is refused, never stored
	if _, err := c.Exec(context.Background(), "INSERT INTO tyall (id, m) VALUES (6, $1)", "nope"); err == nil {
		t.Fatal("an unknown label taken")
	}
	// a UUID's 16 bytes are its text's in order (§4 gives the bytes, not the text): the engine's literal against UUID{0..15}
	want := UUID{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	if got := one(t, c, "SELECT CAST('00010203-0405-0607-0809-0a0b0c0d0e0f' AS UUID)")[0]; got != want {
		t.Fatalf("the literal's UUID: %v", got)
	}
	if got := one(t, c, "SELECT $1 = CAST('00010203-0405-0607-0809-0a0b0c0d0e0f' AS UUID)", want)[0]; got != true {
		t.Fatalf("a UUID parameter against its literal: %v", got)
	}
	// FLOAT64 -0: a -0.0 parameter is sent as 0 and the engine's literal -0.0 stores 0 too (its one zero)
	mustExec(t, c, "INSERT INTO tyall (id, f) VALUES (7, $1), (8, -0.0)", math.Copysign(0, -1))
	for _, id := range []int{7, 8} {
		if got := one(t, c, "SELECT f FROM tyall WHERE id = $1", id)[0]; math.Float64bits(got.(float64)) != 0 {
			t.Fatalf("row %d: %x, want the bits of 0", id, math.Float64bits(got.(float64)))
		}
	}
	// a NULL of no type (0x80): taken into a column (rows above), refused where a type is wanted (§4 does not say where)
	_, err = c.Exec(context.Background(), "SELECT $1", nil)
	var e *Error
	if !errors.As(err, &e) || e.Code != CodeInvalid {
		t.Fatalf("SELECT $1 of a NULL of no type: %v", err)
	}
	t.Logf("SELECT $1 of a NULL of no type: %v", err)
	if got := one(t, c, "SELECT $1", NullOf(TypeDate))[0]; got != nil {
		t.Fatalf("SELECT $1 of a DATE NULL: %v", got)
	}
}

func sameValue(t *testing.T, got, want any) bool {
	// normalize want (a parameter) to what comes back
	switch w := want.(type) {
	case nil, TypedNull:
		return got == nil
	case int16:
		return got == int64(w)
	case int32:
		return got == int64(w)
	case *int32, *bool, *Decimal, *DateTime, *Date, *TimeOfDay, *UUID, *Interval:
		return got == nil
	case sql.NullFloat64, sql.NullString, sql.Null[Decimal], sql.NullTime:
		return got == nil
	case []byte:
		g, ok := got.([]byte)
		if w == nil {
			return got == nil
		}
		return ok && bytes.Equal(g, w)
	case float64:
		g, ok := got.(float64)
		return ok && math.Float64bits(g) == math.Float64bits(w)
	case Decimal:
		g, ok := got.(Decimal)
		return ok && g.String() == w.String()
	case time.Time:
		g, ok := got.(time.Time)
		return ok && g.Equal(w) && g.Location() == time.UTC
	}
	return got == want
}

// TestLiveBatch: a batch runs in order; an ERROR ends it, its index naming the statement, the ones before it kept and the
// ones after it never run.
func TestLiveBatch(t *testing.T) {
	live(t)
	c := dial(t, cfgSock(t, "A"))
	mustExec(t, c, "CREATE TABLE bt (k BIGINT PRIMARY KEY, v TEXT)")
	res, err := c.Batch(context.Background(),
		Statement{SQL: "INSERT INTO bt VALUES ($1, $2)", Args: []any{1, "one"}},
		Statement{SQL: "SELECT k, v FROM bt"},
		Statement{SQL: "INSERT INTO bt VALUES ($1, $2)", Args: []any{1, "again"}}, // the key twice
		Statement{SQL: "INSERT INTO bt VALUES (3, 'three')"})
	var e *Error
	if !errors.As(err, &e) || e.Index != 2 || e.Code != CodeConstraint {
		t.Fatalf("%v, want a constraint at index 2", err)
	}
	if len(res) != 2 || res[0].Done.Count != 1 || len(res[1].Rows) != 1 || res[1].Rows[0][1] != "one" {
		t.Fatalf("the results before the ERROR: %+v", res)
	}
	if n := one(t, c, "SELECT COUNT(*) FROM bt")[0]; n != int64(1) {
		t.Fatalf("%v rows: the statement after the ERROR ran", n)
	}
	if c.TxState() != wire.Idle {
		t.Fatal(c.TxState())
	}
	// a DONE without a read point: a SELECT that reads no table (§4 line 372 says every DONE carries one)
	res, err = c.Batch(context.Background(), Statement{SQL: "SELECT 1 AS one"}, Statement{SQL: "SELECT COUNT(*) FROM bt"})
	if err != nil || res[0].Done.HasRead || !res[1].Done.HasRead || res[1].Done.Read.Commit == 0 {
		t.Fatalf("read points: %v %+v", err, res)
	}
}

// TestLivePrepared: PREPARE, an EXECUTE of several sets (an ERROR's index names its set), DEALLOCATE.
func TestLivePrepared(t *testing.T) {
	live(t)
	c := dial(t, cfgCA(t, "A"))
	ctx := context.Background()
	mustExec(t, c, "CREATE TABLE pt (k BIGINT PRIMARY KEY, v DECIMAL(10,2))")
	if err := c.Prepare(ctx, "pins", "INSERT INTO pt VALUES ($1, $2)"); err != nil {
		t.Fatal(err)
	}
	res, err := c.Execute(ctx, "pins", []any{1, MustDecimal("1.50")}, []any{2, int64(2)}, []any{3, nil})
	if err != nil || len(res) != 3 {
		t.Fatalf("%v %d", err, len(res))
	}
	_, err = c.Execute(ctx, "pins", []any{4, nil}, []any{1, nil}, []any{5, nil})
	var e *Error
	if !errors.As(err, &e) || e.Index != 1 {
		t.Fatalf("%v, want set 1", err)
	}
	if err := c.Prepare(ctx, "psel", "SELECT v FROM pt WHERE k = $1"); err != nil {
		t.Fatal(err)
	}
	res, err = c.Execute(ctx, "psel", []any{1}, []any{2}, []any{3})
	if err != nil || res[0].Rows[0][0].(Decimal).String() != "1.50" || res[1].Rows[0][0].(Decimal).String() != "2.00" ||
		res[2].Rows[0][0] != nil {
		t.Fatalf("%v %+v", err, res)
	}
	if err := c.Deallocate(ctx, "psel"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Execute(ctx, "psel", []any{1}); err == nil {
		t.Fatal("a deallocated statement ran")
	}
}

// TestLiveTransaction: READY's states: idle, in a transaction (a failed statement undone alone), doomed (an ALTER from
// another session), and ROLLBACK back to idle.
func TestLiveTransaction(t *testing.T) {
	live(t)
	c := dial(t, cfgSock(t, "A"))
	o := dial(t, cfgSock(t, "A"))
	mustExec(t, c, "CREATE TABLE tt (k BIGINT PRIMARY KEY)")
	mustExec(t, c, "BEGIN")
	if c.TxState() != wire.InTxn {
		t.Fatal(c.TxState())
	}
	mustExec(t, c, "INSERT INTO tt VALUES (1)")
	if _, err := c.Exec(context.Background(), "INSERT INTO tt VALUES (1)"); err == nil {
		t.Fatal("a duplicate key taken")
	}
	if c.TxState() != wire.InTxn {
		t.Fatalf("after a failed statement: %d", c.TxState())
	}
	if n := one(t, o, "SELECT COUNT(*) FROM tt")[0]; n != int64(0) {
		t.Fatal("another session sees the open transaction's row")
	}
	mustExec(t, c, "COMMIT")
	if c.TxState() != wire.Idle || one(t, o, "SELECT COUNT(*) FROM tt")[0] != int64(1) {
		t.Fatal("COMMIT")
	}
	mustExec(t, c, "BEGIN")
	mustExec(t, c, "INSERT INTO tt VALUES (2)")
	mustExec(t, o, "ALTER TABLE tt ADD COLUMN extra BIGINT")
	_, err := c.Exec(context.Background(), "INSERT INTO tt VALUES (3, 3)")
	t.Logf("a statement after the ALTER: %v; state %d", err, c.TxState())
	if err == nil || c.TxState() != wire.Doomed {
		t.Fatalf("after another session's ALTER: state %d, want doomed", c.TxState())
	}
	_, err = c.Exec(context.Background(), "SELECT 1")
	t.Logf("a SELECT in the doomed transaction: %v; state %d", err, c.TxState())
	if err == nil || c.TxState() != wire.Doomed {
		t.Fatalf("a doomed transaction ran a SELECT: %v, state %d", err, c.TxState())
	}
	mustExec(t, c, "ROLLBACK")
	if c.TxState() != wire.Idle || one(t, o, "SELECT COUNT(*) FROM tt")[0] != int64(1) {
		t.Fatal("ROLLBACK")
	}
	// COMMIT of a doomed transaction: refused, and it ends the transaction (READY idle), nothing of it kept
	mustExec(t, c, "BEGIN")
	mustExec(t, c, "INSERT INTO tt (k) VALUES (5)")
	mustExec(t, o, "ALTER TABLE tt ADD COLUMN extra2 BIGINT")
	_, err = c.Exec(context.Background(), "COMMIT")
	t.Logf("COMMIT of a doomed transaction: %v; state %d", err, c.TxState())
	if err == nil || c.TxState() != wire.Idle || one(t, o, "SELECT COUNT(*) FROM tt")[0] != int64(1) {
		t.Fatal("a doomed transaction's COMMIT")
	}
	// Close is TERMINATE: the server ends the session, its open transaction rolled back (the key free again)
	x, err := Connect(context.Background(), cfgSock(t, "A"))
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, x, "BEGIN")
	mustExec(t, x, "INSERT INTO tt (k) VALUES (9)")
	before, _ := o.Sessions(context.Background())
	x.Close()
	for i := 0; ; i++ {
		after, _ := o.Sessions(context.Background())
		if len(after) == len(before)-1 {
			break
		}
		if i == 100 {
			t.Fatal("the terminated session is still listed")
		}
		time.Sleep(20 * time.Millisecond)
	}
	mustExec(t, o, "INSERT INTO tt (k) VALUES (9)")
}

var bigOnce sync.Once

// bigTable is a 1,000,000-row table loaded by COPY FROM STDIN (the first test needing it makes it).
func bigTable(t *testing.T, c *Conn) {
	t.Helper()
	var err error
	bigOnce.Do(func() {
		if _, err = c.Exec(context.Background(), "CREATE TABLE big (x BIGINT PRIMARY KEY, s TEXT)"); err != nil {
			return
		}
		pr, pw := io.Pipe()
		go func() {
			w := bufio.NewWriterSize(pw, 1<<16)
			for i := 0; i < 1000000; i++ {
				w.WriteString(strconv.Itoa(i))
				w.WriteString(",row ")
				w.WriteString(strconv.Itoa(i))
				w.WriteByte('\n')
			}
			w.Flush()
			pw.Close()
		}()
		var d *Done
		d, err = c.CopyFrom(context.Background(), "COPY big FROM STDIN", pr)
		if err == nil && d.Count != 1000000 {
			err = fmt.Errorf("COPY wrote %d rows", d.Count)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
}

const longJoin = "SELECT COUNT(*) FROM big AS a JOIN big AS b ON a.x + b.x = -1"

// running waits until the session other than the asker's is running a request (SESSIONS' state 1).
func running(t *testing.T, asker *Conn) uint64 {
	t.Helper()
	for i := 0; i < 200; i++ {
		ss, err := asker.Sessions(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range ss {
			if s.State == wire.SessRunning {
				time.Sleep(100 * time.Millisecond) // picked: its statement under way
				return s.ID
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("no session ran")
	return 0
}

// TestLiveCancel: a self-join of a 1,000,000-row table cancelled from another goroutine (in band), by a context's
// deadline, and by KILL from another connection; the session idle after each.
func TestLiveCancel(t *testing.T) {
	live(t)
	for _, mk := range []func(*testing.T, string) Config{cfgSock, cfgCA} {
		c := dial(t, mk(t, "A"))
		op := dial(t, mk(t, "A"))
		bigTable(t, c)
		// Cancel from another goroutine
		done := make(chan error)
		go func() { _, err := c.Exec(context.Background(), longJoin); done <- err }()
		running(t, op)
		start := time.Now()
		c.Cancel()
		err := <-done
		var e *Error
		if !errors.As(err, &e) || e.Code != CodeCancelled || c.TxState() != wire.Idle || c.Err() != nil {
			t.Fatalf("Cancel: %v", err)
		}
		t.Logf("cancelled in %v", time.Since(start))
		// a context's deadline
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		_, err = c.Exec(ctx, longJoin)
		cancel()
		if !errors.As(err, &e) || e.Code != CodeCancelled || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("a deadline: %v", err)
		}
		// KILL cancel from another connection
		go func() { _, err := c.Exec(context.Background(), longJoin); done <- err }()
		id := running(t, op)
		found, err := op.Kill(context.Background(), id, KillCancel)
		if err != nil || !found {
			t.Fatalf("KILL cancel: %v %v", found, err)
		}
		if err := <-done; !errors.As(err, &e) || e.Code != CodeCancelled {
			t.Fatalf("KILL cancel: %v", err)
		}
		if one(t, c, "SELECT 7")[0] != int64(7) { // the session goes on
			t.Fatal("after the cancels")
		}
	}
}

// TestLiveOutOfTurn: the protocol's level: PING sent while a request runs is answered at once (PONG out of turn),
// SESSIONS too; requests pipeline and are answered in order.
func TestLiveOutOfTurn(t *testing.T) {
	live(t)
	c := dial(t, cfgSock(t, "A"))
	bigTable(t, c)
	if err := c.Send(wire.Query{Stmts: []wire.Statement{{SQL: longJoin}}}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if err := c.Send(wire.Ping{}); err != nil {
		t.Fatal(err)
	}
	if err := c.Send(wire.Sessions{}); err != nil {
		t.Fatal(err)
	}
	m, err := c.Next()
	if err != nil || m.Type() != wire.TPong {
		t.Fatalf("%v %v, want PONG while the join runs", m, err)
	}
	m, err = c.Next()
	if err != nil || m.Type() != wire.TSessionsList {
		t.Fatalf("%v %v, want SESSIONS_LIST", m, err)
	}
	c.Cancel()
	for _, w := range []wire.FrameType{wire.TError, wire.TReady} {
		if m, err = c.Next(); err != nil || m.Type() != w {
			t.Fatalf("%v %v, want %s", m, err, w)
		}
	}
	// three requests pipelined, each answered in full in order
	for i := 1; i <= 3; i++ {
		if err := c.Send(wire.Query{Stmts: []wire.Statement{{SQL: "SELECT $1", Params: []wire.Value{{Type: wire.TypeInt64, I: int64(i)}}}}}); err != nil {
			t.Fatal(err)
		}
	}
	for i := 1; i <= 3; i++ {
		var got int64
		for {
			m, err := c.Next()
			if err != nil {
				t.Fatal(err)
			}
			if r, ok := m.(wire.Rows); ok {
				row, _ := r.Iter().Next(nil)
				got = row[0].I
			}
			if m.Type() == wire.TReady {
				break
			}
		}
		if got != int64(i) {
			t.Fatalf("reply %d carried %d", i, got)
		}
	}
	if c.Ping(context.Background()) != nil {
		t.Fatal("ping")
	}
}

// TestLiveCopy: COPY both ways (1,000,000 rows), a client's failure (COPY_FAIL), a COPY refused before its data.
func TestLiveCopy(t *testing.T) {
	live(t)
	c := dial(t, cfgCA(t, "A"))
	bigTable(t, c)
	var buf bytes.Buffer
	d, err := c.CopyTo(context.Background(), "COPY big TO STDOUT", &buf)
	if err != nil || d.Count != 1000000 {
		t.Fatalf("COPY TO: %v %+v", err, d)
	}
	h := sha256.New()
	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	if len(lines) != 1000000 {
		t.Fatalf("%d lines", len(lines))
	}
	seen := make([]bool, 1000000)
	for _, l := range lines {
		k, s, _ := strings.Cut(l, ",")
		x, err := strconv.Atoi(k)
		if err != nil || s != "row "+k || seen[x] {
			t.Fatalf("line %q", l)
		}
		seen[x] = true
	}
	h.Write(buf.Bytes())
	// a reader that fails part way: COPY_FAIL, the statement refused unrun, nothing written
	mustExec(t, c, "CREATE TABLE cf (k BIGINT PRIMARY KEY)")
	r := io.MultiReader(strings.NewReader("1\n2\n"), readerFunc(func([]byte) (int, error) { return 0, errors.New("disk gone") }))
	_, err = c.CopyFrom(context.Background(), "COPY cf FROM STDIN", r)
	var e *Error
	if !errors.As(err, &e) || e.Code != CodeCancelled || !strings.Contains(e.Message, "disk gone") {
		t.Fatalf("COPY_FAIL: %v", err)
	}
	if one(t, c, "SELECT COUNT(*) FROM cf")[0] != int64(0) {
		t.Fatal("a failed COPY wrote rows")
	}
	// refused before its data: no COPY_IN, the reader never read
	read := false
	_, err = c.CopyFrom(context.Background(), "COPY nosuch FROM STDIN", readerFunc(func([]byte) (int, error) {
		read = true
		return 0, io.EOF
	}))
	if err == nil || read {
		t.Fatalf("a COPY into no table: %v, read %v", err, read)
	}
	// bad data answered after COPY_DONE, by line
	_, err = c.CopyFrom(context.Background(), "COPY cf FROM STDIN", strings.NewReader("1\nx\n"))
	if !errors.As(err, &e) || !strings.Contains(e.Message, "line 2") {
		t.Fatalf("bad data: %v", err)
	}
	// a COPY through Exec is refused unrun, the connection in step
	if _, err := c.Exec(context.Background(), "COPY cf FROM STDIN"); err == nil {
		t.Fatal("a COPY through Exec")
	}
	if one(t, c, "SELECT 1")[0] != int64(1) {
		t.Fatal("the connection out of step")
	}
	// CopyFrom given a COPY ... TO STDOUT: its data read and dropped to READY, refused, the connection in step
	_, err = c.CopyFrom(context.Background(), "COPY big TO STDOUT", strings.NewReader("1\n"))
	if !errors.As(err, &e) || e.Code != CodeState || c.Err() != nil || one(t, c, "SELECT 2")[0] != int64(2) {
		t.Fatalf("CopyFrom of a COPY TO: %v", err)
	}
}

// TestLiveStream: a result of 1,000,000 rows read through Query as it comes (many ROWS frames, each read against its
// COLUMNS), every row exact; and at the protocol's level, the frames counted.
func TestLiveStream(t *testing.T) {
	live(t)
	c := dial(t, cfgCA(t, "A"))
	bigTable(t, c)
	r, err := c.Query(context.Background(), "SELECT x, s FROM big")
	if err != nil {
		t.Fatal(err)
	}
	seen := make([]bool, 1000000)
	n := 0
	for r.Next() {
		var x int64
		var s string
		if err := r.Scan(&x, &s); err != nil {
			t.Fatal(err)
		}
		if x < 0 || x >= 1000000 || seen[x] || s != "row "+strconv.FormatInt(x, 10) {
			t.Fatalf("row %d: %d %q", n, x, s)
		}
		seen[x] = true
		n++
	}
	if r.Err() != nil || n != 1000000 || r.Done().Count != 1000000 {
		t.Fatalf("%d rows, %v", n, r.Err())
	}
	r.Close()
	if err := c.Send(wire.Query{Stmts: []wire.Statement{{SQL: "SELECT x, s FROM big"}}}); err != nil {
		t.Fatal(err)
	}
	frames, rows := 0, 0
	for {
		m, err := c.Next()
		if err != nil {
			t.Fatal(err)
		}
		if rm, ok := m.(wire.Rows); ok {
			frames++
			it := rm.Iter()
			var buf []wire.Value
			for {
				var ok bool
				if buf, ok = it.Next(buf); !ok {
					break
				}
				rows++
			}
		}
		if m.Type() == wire.TReady {
			break
		}
	}
	if rows != 1000000 || frames < 2 {
		t.Fatalf("%d rows in %d ROWS frames", rows, frames)
	}
	t.Logf("1,000,000 rows in %d ROWS frames", frames)
}

// TestLiveSessionsKill: SESSIONS lists the sessions; KILL terminates another (its next request meets ERROR 15 and the
// close), a KILL of no such session is code 1; a send after the server closed reports the server's last ERROR.
func TestLiveSessionsKill(t *testing.T) {
	live(t)
	for _, tcp := range []bool{false, true} {
		mk := cfgSock
		if tcp {
			mk = cfgPin
		}
		op := dial(t, mk(t, "A"))
		victim := dial(t, mk(t, "A"))
		ss, err := op.Sessions(context.Background())
		if err != nil || len(ss) < 2 {
			t.Fatalf("%v %v", ss, err)
		}
		id := ss[len(ss)-1].ID // the latest connection's
		if ss[len(ss)-1].Name != env(t, "IMDB_USER") || (ss[len(ss)-1].Endpoint == 1) != tcp {
			t.Fatalf("the session: %+v", ss[len(ss)-1])
		}
		if found, err := op.Kill(context.Background(), id+1000000, KillTerminate); err != nil || found {
			t.Fatalf("no such session: %v %v", found, err)
		}
		mustExec(t, victim, "BEGIN")
		if found, err := op.Kill(context.Background(), id, KillTerminate); err != nil || !found {
			t.Fatalf("terminate: %v %v", found, err)
		}
		if tcp { // over TCP the first write after the close is taken by the kernel: the words read as a reply (at once:
			// the server answers no frame after a KILL_DONE, its race fixed 11-22 with the server's server_kill_wake)
			_, err = victim.Exec(context.Background(), "SELECT 1")
		} else { // the socket: past the server's lingering close (1 s), the send itself fails
			time.Sleep(1500 * time.Millisecond)
			err = victim.Send(wire.Query{Stmts: []wire.Statement{{SQL: "SELECT 1"}}})
		}
		var e *Error
		if !errors.As(err, &e) || e.Code != CodeCancelled || !e.Closed || e.Index != 0 || !strings.Contains(e.Message, "KILL") {
			t.Fatalf("after a KILL (tcp %v): %v", tcp, err)
		}
		if _, err := victim.Exec(context.Background(), "SELECT 1"); err == nil {
			t.Fatal("a killed connection used")
		}
	}
}

// TestLiveSQL: database/sql end to end, by DSN, through the socket and TCP.
func TestLiveSQL(t *testing.T) {
	live(t)
	dsns := []string{
		fmt.Sprintf("imagedb://%s?user=%s&password=%s", env(t, "IMDB_A_SOCK"), env(t, "IMDB_USER"), env(t, "IMDB_PASSWORD")),
		fmt.Sprintf("imagedb://%s:%s@%s/?ca=%s", env(t, "IMDB_USER"), env(t, "IMDB_PASSWORD"), env(t, "IMDB_A_ADDR"), env(t, "IMDB_A_CA")),
		fmt.Sprintf("imagedb://%s:%s@%s/?pin=%s&binding=tls-server-end-point", env(t, "IMDB_USER"), env(t, "IMDB_PASSWORD"),
			env(t, "IMDB_B_ADDR"), env(t, "IMDB_B_PIN")),
	}
	for k, dsn := range dsns {
		db, err := sql.Open("imagedb", dsn)
		if err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		tbl := fmt.Sprintf("sq%d", k)
		if _, err := db.ExecContext(ctx, "CREATE TABLE "+tbl+" (k BIGINT PRIMARY KEY, d DECIMAL(12,3), t TEXT, ts TIMESTAMPTZ, u UUID)"); err != nil {
			t.Fatal(err)
		}
		ts := time.Date(2026, 11, 19, 12, 30, 0, 123456000, time.UTC)
		res, err := db.ExecContext(ctx, "INSERT INTO "+tbl+" VALUES ($1, $2, $3, $4, $5), ($6, $7, $8, $9, $10)",
			1, MustDecimal("12.345"), "é", ts, UUID{9}, 2, sql.Null[Decimal]{}, sql.NullString{}, sql.NullTime{}, (*UUID)(nil))
		if err != nil {
			t.Fatal(err)
		}
		if n, _ := res.RowsAffected(); n != 2 {
			t.Fatalf("%d rows", n)
		}
		var d Decimal
		var s sql.NullString
		var tt time.Time
		var u UUID
		if err := db.QueryRowContext(ctx, "SELECT d, t, ts, u FROM "+tbl+" WHERE k = $1", 1).Scan(&d, &s, &tt, &u); err != nil {
			t.Fatal(err)
		}
		if d.String() != "12.345" || s.String != "é" || !tt.Equal(ts) || u != (UUID{9}) {
			t.Fatalf("%v %v %v %v", d, s, tt, u)
		}
		var nd *Decimal
		var nt sql.NullTime
		if err := db.QueryRowContext(ctx, "SELECT d, ts FROM "+tbl+" WHERE k = 2").Scan(&nd, &nt); err != nil || nd != nil || nt.Valid {
			t.Fatalf("NULLs: %v %v %v", nd, nt, err)
		}
		// a prepared statement (PREPARE on the server, EXECUTE, DEALLOCATE at Close)
		st, err := db.PrepareContext(ctx, "SELECT t FROM "+tbl+" WHERE k = $1")
		if err != nil {
			t.Fatal(err)
		}
		var got sql.NullString
		if err := st.QueryRowContext(ctx, 1).Scan(&got); err != nil || got.String != "é" {
			t.Fatal(got, err)
		}
		st.Close()
		// transactions: a rollback leaves nothing, a commit keeps it
		tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
		if err != nil {
			t.Fatal(err)
		}
		tx.ExecContext(ctx, "INSERT INTO "+tbl+" (k) VALUES (3)")
		tx.Rollback()
		tx, _ = db.BeginTx(ctx, nil)
		tx.ExecContext(ctx, "INSERT INTO "+tbl+" (k) VALUES (4)")
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		var n int64
		db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+tbl).Scan(&n)
		if n != 3 {
			t.Fatalf("%d rows after the transactions", n)
		}
		if _, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true}); err == nil {
			t.Fatal("a read-only transaction")
		}
		rows, err := db.QueryContext(ctx, "SELECT k, d FROM "+tbl+" ORDER BY k")
		if err != nil {
			t.Fatal(err)
		}
		ct, _ := rows.ColumnTypes()
		if p, s, ok := ct[1].DecimalSize(); !ok || p != 38 || s != 3 || ct[1].DatabaseTypeName() != "DECIMAL" ||
			ct[0].ScanType().Kind().String() != "int64" {
			t.Fatalf("column types: %v %v %v", p, s, ok)
		}
		rows.Close()
		if err := db.PingContext(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, "SELECT $a", sql.Named("a", 1)); err == nil {
			t.Fatal("a named parameter")
		}
		db.Close()
	}
}

// TestLiveSQLCancel: database/sql's context ends the long join on the server (CANCEL, ERROR 15) and the pool's one
// connection goes on: the next query on it answers.
func TestLiveSQLCancel(t *testing.T) {
	live(t)
	bigTable(t, dial(t, cfgSock(t, "A")))
	db, err := sql.Open("imagedb", fmt.Sprintf("imagedb://%s?user=%s&password=%s", env(t, "IMDB_A_SOCK"), env(t, "IMDB_USER"),
		env(t, "IMDB_PASSWORD")))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	for i := 0; i < 3; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		start := time.Now()
		var n int64
		err := db.QueryRowContext(ctx, longJoin).Scan(&n)
		cancel()
		var e *Error
		if !errors.As(err, &e) || e.Code != CodeCancelled || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("round %d: %v", i, err)
		}
		if took := time.Since(start); took > 5*time.Second {
			t.Fatalf("round %d: the cancel took %v", i, took)
		}
		if err := db.QueryRowContext(context.Background(), "SELECT 41 + 1").Scan(&n); err != nil || n != 42 {
			t.Fatalf("round %d: the connection after the cancel: %v %d", i, err, n)
		}
	}
	if s := db.Stats(); s.OpenConnections != 1 {
		t.Fatalf("%d connections: the cancelled one was dropped", s.OpenConnections)
	}
}
