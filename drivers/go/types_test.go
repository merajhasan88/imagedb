package imagedb

import (
	"bytes"
	"database/sql"
	"encoding/hex"
	"math"
	"math/big"
	"strings"
	"testing"
	"time"

	"imagedb.dev/imagedb/wire"
)

func wireHex(t *testing.T, x any) string {
	t.Helper()
	v, err := ToValue(x)
	if err != nil {
		t.Fatalf("ToValue(%#v): %v", x, err)
	}
	b, err := wire.AppendValue(nil, &v)
	if err != nil {
		t.Fatalf("AppendValue(%#v): %v", x, err)
	}
	return hex.EncodeToString(b)
}

func fromHex(t *testing.T, h string) any {
	t.Helper()
	b, _ := hex.DecodeString(strings.ReplaceAll(h, " ", ""))
	v, off, err := wire.DecodeValue(b, 0)
	if err != nil || off != len(b) {
		t.Fatalf("%s: %v", h, err)
	}
	return FromValue(&v)
}

// TestNativeVectors: each native type to §4's vectors (t_wire.c lines 55-84) and back.
func TestNativeVectors(t *testing.T) {
	u := UUID{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	cases := []struct {
		go_  any
		hex  string
		back any // FromValue's
	}{
		{int64(-2), "01feffffffffffffff", int64(-2)},
		{int64(math.MinInt64), "010000000000000080", int64(math.MinInt64)},
		{1.5, "02000000000000f83f", 1.5},
		{true, "0301", true},
		{"hé", "040300000068c3a9", "hé"},
		{MustDecimal("-123.45"), "0502c7cfffffffffffffffffffffffffffff", MustDecimal("-123.45")},
		{DateTime{Date{1, 1, 1}, TimeOfDay{}}, "060040d400014023ff", DateTime{Date{1, 1, 1}, TimeOfDay{}}},
		{time.Date(9999, 12, 31, 23, 59, 59, 999999000, time.UTC), "07ff5f73cc0c448403",
			time.Date(9999, 12, 31, 23, 59, 59, 999999000, time.UTC)},
		{Date{1, 1, 1}, "08c606f5ff", Date{1, 1, 1}},
		{Date{9999, 12, 31}, "08a0c02c00", Date{9999, 12, 31}},
		{TimeOfDay{23, 59, 59, 999999}, "09ff5fd71d14000000", TimeOfDay{23, 59, 59, 999999}},
		{u, "0a000102030405060708090a0b0c0d0e0f", u},
		{[]byte{0, 0xff}, "0b0200000000ff", []byte{0, 0xff}},
		{Interval{1, -2, 3}, "0c01000000feffffff0300000000000000", Interval{1, -2, 3}},
		{Interval{math.MinInt32, math.MaxInt32, math.MinInt64}, "0c00000080ffffff7f0000000000000080",
			Interval{math.MinInt32, math.MaxInt32, math.MinInt64}},
		{nil, "80", nil},
		{(*int64)(nil), "81", nil},
		{NullOf(TypeDecimal), "85", nil},
		{NullOf(TypeEnum), "8d", nil},
	}
	for _, c := range cases {
		if got := wireHex(t, c.go_); got != c.hex {
			t.Fatalf("%#v: %s, want %s", c.go_, got, c.hex)
		}
		back := fromHex(t, c.hex)
		switch b := back.(type) {
		case Decimal:
			if b.String() != c.back.(Decimal).String() {
				t.Fatalf("%s back: %v", c.hex, b)
			}
		case []byte:
			if !bytes.Equal(b, c.back.([]byte)) {
				t.Fatalf("%s back: %v", c.hex, b)
			}
		case time.Time:
			if !b.Equal(c.back.(time.Time)) || b.Location() != time.UTC {
				t.Fatalf("%s back: %v", c.hex, b)
			}
		default:
			if back != c.back {
				t.Fatalf("%s back: %#v, want %#v", c.hex, back, c.back)
			}
		}
	}
	// an ENUM's label comes back as a string; TEXT's empty one too
	if fromHex(t, "0d0161") != "a" || fromHex(t, "0d00") != "" || fromHex(t, "0400000000") != "" {
		t.Fatal("ENUM or empty TEXT")
	}
	// FLOAT64 bit-exact: the smallest subnormal, the largest finite, the one zero
	for _, f := range []float64{math.SmallestNonzeroFloat64, math.MaxFloat64, -math.MaxFloat64, 0, 0.1} {
		v, _ := ToValue(f)
		if back := FromValue(&v).(float64); math.Float64bits(back) != math.Float64bits(f) {
			t.Fatalf("%v back %v", f, back)
		}
	}
}

func TestParamRules(t *testing.T) {
	// typed NULLs: the engine binds a NULL by its type
	for _, c := range []struct {
		x   any
		hex string
	}{
		{sql.NullString{}, "84"}, {sql.NullInt64{}, "81"}, {sql.NullFloat64{}, "82"}, {sql.NullBool{}, "83"},
		{sql.NullTime{}, "87"}, {sql.Null[Decimal]{}, "85"}, {sql.Null[Date]{}, "88"}, {sql.Null[UUID]{}, "8a"},
		{[]byte(nil), "8b"}, {(*Interval)(nil), "8c"}, {(*TimeOfDay)(nil), "89"}, {(*DateTime)(nil), "86"},
		{(**string)(nil), "84"}, {NullOf(TypeNone), "80"}, {(*Decimal)(nil), "85"}, {(*big.Int)(nil), "85"},
		{sql.NullInt64{Int64: 7, Valid: true}, "010700000000000000"}, {sql.Null[string]{V: "a", Valid: true}, "040100000061"},
		{int8(-1), "01ffffffffffffffff"}, {uint32(math.MaxUint32), "01ffffffff00000000"},
		{uint64(math.MaxUint64), "0500ffffffffffffffff0000000000000000"}, // past INT64: a DECIMAL of scale 0
		{big.NewInt(-5), "0500fbffffffffffffffffffffffffffffff"},
		{float32(1.5), "02000000000000f83f"},
		{90 * time.Second, "0c0000000000000000804a5d0500000000"},
		{[16]byte{15: 1}, "0a00000000000000000000000000000001"},
	} {
		if got := wireHex(t, c.x); got != c.hex {
			t.Fatalf("%#v: %s, want %s", c.x, got, c.hex)
		}
	}
	type myInt int32
	type myStr string
	if wireHex(t, myInt(3)) != "010300000000000000" || wireHex(t, myStr("b")) != "040100000062" {
		t.Fatal("named types")
	}
	// refused, never reinterpreted or rounded
	// -0 sent as 0 (the engine keeps one zero; its literal -0.0 stores 0: TestLiveTypes), while the codec itself refuses -0
	if wireHex(t, math.Copysign(0, -1)) != "020000000000000000" || wireHex(t, float32(math.Copysign(0, -1))) != "020000000000000000" {
		t.Fatal("-0 not sent as 0")
	}
	if _, err := wire.AppendValue(nil, &wire.Value{Type: wire.TypeFloat64, F: 0x8000000000000000}); err == nil {
		t.Fatal("the codec took -0")
	}
	for _, x := range []any{math.NaN(), math.Inf(1), "a\x00b", "\xff", strings.Repeat("a", 65536),
		make([]byte, 65536), time.Date(2026, 1, 1, 0, 0, 0, 1, time.UTC), time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC),
		Date{2023, 2, 29}, Date{0, 12, 31}, TimeOfDay{24, 0, 0, 0}, TimeOfDay{0, 60, 0, 0}, time.Nanosecond,
		DateTime{Date{2026, 13, 1}, TimeOfDay{}}, struct{}{}, []int{1}, wire.Value{Type: wire.TypeEnum, S: []byte("a")},
		NullOf(14)} {
		if _, err := ToValue(x); err == nil {
			t.Fatalf("%#v taken", x)
		}
	}
}

func TestDecimal(t *testing.T) {
	for _, s := range []string{"0", "1.50", "-0.001", "99999999999999999999999999999999999999",
		"-9999999999999999999999999999999999999.9", "0.00000000000000000000000000000000000001", "123"} {
		d, err := ParseDecimal(s)
		if err != nil || d.String() != s {
			t.Fatalf("%s: %v %v", s, d, err)
		}
		v := d.toWire()
		if !wire.ValueOK(&v) || decimalFromWire(&v).String() != s {
			t.Fatalf("%s through the wire", s)
		}
		var e Decimal
		if err := e.Compose(d.Decompose(nil)); err != nil || e.String() != s {
			t.Fatalf("%s decomposed: %v %v", s, e, err)
		}
	}
	for _, s := range []string{"", ".", "+", "1e5", "1.2.3", "100000000000000000000000000000000000000", "0x10", " 1"} {
		if _, err := ParseDecimal(s); err == nil {
			t.Fatalf("%q taken", s)
		}
	}
	if MustDecimal("1.5").Cmp(MustDecimal("1.50")) != 0 || MustDecimal("1.5").String() == MustDecimal("1.50").String() {
		t.Fatal("a scale kept, a number compared")
	}
	var d Decimal
	if err := d.Compose(0, false, []byte{12}, 2); err != nil || d.String() != "1200" {
		t.Fatalf("12e2: %v %v", d, err)
	}
	if err := d.Compose(0, true, big.NewInt(1500).Bytes(), -40); err != nil || d.String() != "-0.00000000000000000000000000000000000015" {
		t.Fatalf("trailing zeros past 38: %v %v", d, err)
	}
	if err := d.Compose(0, false, []byte{1}, -39); err == nil {
		t.Fatal("a 39th place rounded")
	}
	if err := d.Compose(1, false, nil, 0); err == nil {
		t.Fatal("an infinity taken")
	}
	if fmtZero := (Decimal{}).String(); fmtZero != "0" {
		t.Fatal(fmtZero)
	}
}

func TestCivil(t *testing.T) {
	for days := int32(wire.DateMin); days <= wire.DateMax; days += 997 {
		d := DateFromDays(days)
		if got, err := d.Days(); err != nil || got != days {
			t.Fatalf("%d: %v %d %v", days, d, got, err)
		}
	}
	for us := int64(wire.TimestampMin); us <= wire.TimestampMax-1e12; us += 7919e11 + 123457 {
		dt := DateTimeFromMicros(us)
		if got, err := dt.Micros(); err != nil || got != us {
			t.Fatalf("%d: %v %d %v", us, dt, got, err)
		}
	}
	if s := (DateTime{Date{2026, 11, 19}, TimeOfDay{1, 2, 3, 4}}).String(); s != "2026-11-19 01:02:03.000004" {
		t.Fatal(s)
	}
	u, err := ParseUUID("000102030405060708090A0B0C0D0E0F")
	if err == nil {
		t.Fatal("a UUID without hyphens taken")
	}
	u, err = ParseUUID("00010203-0405-0607-0809-0A0B0C0D0E0F")
	if err != nil || u.String() != "00010203-0405-0607-0809-0a0b0c0d0e0f" {
		t.Fatal(u, err)
	}
}

func TestDSN(t *testing.T) {
	cfg, err := ParseDSN("imagedb:///dev/shm/x/s.sock?user=admin&password=p%26w")
	if err != nil || cfg.Socket != "/dev/shm/x/s.sock" || cfg.User != "admin" || cfg.Password != "p&w" || cfg.Addr != "" {
		t.Fatalf("%+v %v", cfg, err)
	}
	pin := strings.Repeat("ab", 32)
	cfg, err = ParseDSN("imagedb://admin:pw@127.0.0.1:5000/?pin=" + pin + "&binding=tls-server-end-point&read_timeout=5s")
	if err != nil || cfg.Addr != "127.0.0.1:5000" || len(cfg.Pin) != 32 || cfg.Binding != BindingEndpoint ||
		cfg.ReadTimeout != 5*time.Second || cfg.Password != "pw" {
		t.Fatalf("%+v %v", cfg, err)
	}
	for _, bad := range []string{"postgres://x", "imagedb://h:1/?pin=00", "imagedb://h:1/?nope=1", "imagedb://h:1/path",
		"imagedb://h:1/?binding=none", "imagedb://h:1/?socket=/s", "imagedb://h:1/?read_timeout=x",
		"imagedb://h:1/?user=a&user=b"} {
		if _, err := ParseDSN(bad); err == nil {
			t.Fatalf("%s taken", bad)
		}
	}
}
