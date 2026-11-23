package imagedb

import (
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/big"
	"math/bits"
	"reflect"
	"strings"
	"time"

	"imagedb.dev/imagedb/wire"
)

// Type is a value's wire type (docs/n1-design.md §4).
type Type = wire.Type

// The wire types.
const (
	TypeNone        = wire.TypeNone
	TypeInt64       = wire.TypeInt64
	TypeFloat64     = wire.TypeFloat64
	TypeBool        = wire.TypeBool
	TypeText        = wire.TypeText
	TypeDecimal     = wire.TypeDecimal
	TypeTimestamp   = wire.TypeTimestamp
	TypeTimestampTZ = wire.TypeTimestampTZ
	TypeDate        = wire.TypeDate
	TypeTime        = wire.TypeTime
	TypeUUID        = wire.TypeUUID
	TypeBytea       = wire.TypeBytea
	TypeInterval    = wire.TypeInterval
	TypeEnum        = wire.TypeEnum
)

// TypedNull is a NULL parameter of a type: the engine binds a NULL by its type, so a NULL keeps one. A plain nil is a
// NULL of no type, which the engine takes into any column (and refuses where a type is wanted, as a literal NULL).
type TypedNull struct{ Type Type }

// NullOf is a NULL of type t.
func NullOf(t Type) TypedNull { return TypedNull{Type: t} }

// ---- DECIMAL ----

// Decimal is an exact DECIMAL: Unscaled × 10^-Scale, |Unscaled| < 10^38, Scale 0 to 38 (math/big's big.Int, held
// immutable: every accessor copies). Its scale is kept: 1.50 is (150, 2), never 1.5. The zero value is 0 at scale 0.
type Decimal struct {
	u     *big.Int
	scale uint8
}

var bigTen = big.NewInt(10)

func pow10Big(k int) *big.Int { return new(big.Int).Exp(bigTen, big.NewInt(int64(k)), nil) }

var decLimit = pow10Big(wire.DecimalMax) // 10^38

// NewDecimal is unscaled × 10^-scale; refused past 38 digits or a scale past 38.
func NewDecimal(unscaled *big.Int, scale int) (Decimal, error) {
	if scale < 0 || scale > wire.DecimalMax {
		return Decimal{}, fmt.Errorf("imagedb: a DECIMAL's scale is 0 to 38, not %d", scale)
	}
	if unscaled == nil {
		unscaled = new(big.Int)
	}
	if new(big.Int).Abs(unscaled).Cmp(decLimit) >= 0 {
		return Decimal{}, errors.New("imagedb: a DECIMAL holds at most 38 digits")
	}
	return Decimal{u: new(big.Int).Set(unscaled), scale: uint8(scale)}, nil
}

// DecimalFromInt64 is v at scale 0.
func DecimalFromInt64(v int64) Decimal { return Decimal{u: big.NewInt(v)} }

// ParseDecimal reads [+-]digits[.digits] exactly: its scale is the digits after the point ("1.50": scale 2).
func ParseDecimal(s string) (Decimal, error) {
	t := s
	neg := false
	if t != "" && (t[0] == '+' || t[0] == '-') {
		neg = t[0] == '-'
		t = t[1:]
	}
	ip, fp, dot := strings.Cut(t, ".")
	if (ip == "" && fp == "") || (dot && fp == "" && ip == "") || !digitsOnly(ip) || !digitsOnly(fp) {
		return Decimal{}, fmt.Errorf("imagedb: %q is not a decimal number", s)
	}
	u, ok := new(big.Int).SetString(ip+fp, 10)
	if !ok {
		return Decimal{}, fmt.Errorf("imagedb: %q is not a decimal number", s)
	}
	if neg {
		u.Neg(u)
	}
	return NewDecimal(u, len(fp))
}

func digitsOnly(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// MustDecimal is ParseDecimal, panicking on a malformed literal (for constants).
func MustDecimal(s string) Decimal {
	d, err := ParseDecimal(s)
	if err != nil {
		panic(err)
	}
	return d
}

func (d Decimal) big() *big.Int {
	if d.u == nil {
		return new(big.Int)
	}
	return d.u
}

// Unscaled is the unscaled integer (a copy).
func (d Decimal) Unscaled() *big.Int { return new(big.Int).Set(d.big()) }

// Scale is the digits after the point.
func (d Decimal) Scale() int { return int(d.scale) }

// Rat is the exact value as a big.Rat.
func (d Decimal) Rat() *big.Rat { return new(big.Rat).SetFrac(d.Unscaled(), pow10Big(int(d.scale))) }

// Cmp compares the numbers (1.5 and 1.50 equal).
func (d Decimal) Cmp(e Decimal) int { return d.Rat().Cmp(e.Rat()) }

// String is the number at its scale ("-123.45", "0.00").
func (d Decimal) String() string {
	u := d.big()
	s := new(big.Int).Abs(u).String()
	if d.scale > 0 {
		if len(s) <= int(d.scale) {
			s = strings.Repeat("0", int(d.scale)-len(s)+1) + s
		}
		s = s[:len(s)-int(d.scale)] + "." + s[len(s)-int(d.scale):]
	}
	if u.Sign() < 0 {
		s = "-" + s
	}
	return s
}

// Decompose is database/sql's decimal interface (form 0: finite; the coefficient big-endian; exponent -Scale), so a
// Decimal scans into any decimal type that implements Compose.
func (d Decimal) Decompose(buf []byte) (form byte, negative bool, coefficient []byte, exponent int32) {
	u := d.big()
	return 0, u.Sign() < 0, append(buf[:0], new(big.Int).Abs(u).Bytes()...), -int32(d.scale)
}

// Compose sets d from database/sql's decimal interface; refused unless finite and exact within 38 digits and scale 38.
func (d *Decimal) Compose(form byte, negative bool, coefficient []byte, exponent int32) error {
	if form != 0 {
		return errors.New("imagedb: a DECIMAL is finite (no NaN or infinity)")
	}
	u := new(big.Int).SetBytes(coefficient)
	if negative {
		u.Neg(u)
	}
	scale := -int64(exponent)
	if scale < 0 {
		if -scale > wire.DecimalMax {
			return errors.New("imagedb: a DECIMAL holds at most 38 digits")
		}
		u.Mul(u, pow10Big(int(-scale)))
		scale = 0
	}
	for scale > wire.DecimalMax { // trailing zeros only: never a rounding
		q, r := new(big.Int).QuoRem(u, bigTen, new(big.Int))
		if r.Sign() != 0 {
			return errors.New("imagedb: a DECIMAL's scale is at most 38 (no rounding)")
		}
		u, scale = q, scale-1
	}
	nd, err := NewDecimal(u, int(scale))
	if err != nil {
		return err
	}
	*d = nd
	return nil
}

// Scan is database/sql's Scanner: from a Decimal, a decimal text, an int64, or anything decimal-decomposable.
func (d *Decimal) Scan(src any) error {
	switch s := src.(type) {
	case Decimal:
		*d = s
		return nil
	case string:
		x, err := ParseDecimal(s)
		if err == nil {
			*d = x
		}
		return err
	case []byte:
		return d.Scan(string(s))
	case int64:
		*d = DecimalFromInt64(s)
		return nil
	case decomposer:
		return d.Compose(s.Decompose(nil))
	}
	return fmt.Errorf("imagedb: cannot scan %T into a Decimal", src)
}

type decomposer interface {
	Decompose(buf []byte) (form byte, negative bool, coefficient []byte, exponent int32)
}

// toWire is the two's-complement i128 hi:lo of d's unscaled value.
func (d Decimal) toWire() wire.Value {
	u := d.big()
	m := new(big.Int).Abs(u)
	var w [16]byte
	m.FillBytes(w[:]) // |u| < 10^38 < 2^127: fits
	hi := uint64(w[0])<<56 | uint64(w[1])<<48 | uint64(w[2])<<40 | uint64(w[3])<<32 | uint64(w[4])<<24 | uint64(w[5])<<16 | uint64(w[6])<<8 | uint64(w[7])
	lo := uint64(w[8])<<56 | uint64(w[9])<<48 | uint64(w[10])<<40 | uint64(w[11])<<32 | uint64(w[12])<<24 | uint64(w[13])<<16 | uint64(w[14])<<8 | uint64(w[15])
	if u.Sign() < 0 {
		var c uint64
		lo, c = bits.Add64(^lo, 1, 0)
		hi = ^hi + c
	}
	return wire.Value{Type: wire.TypeDecimal, Scale: d.scale, Hi: int64(hi), Lo: lo}
}

func decimalFromWire(v *wire.Value) Decimal {
	hi, lo := uint64(v.Hi), v.Lo
	neg := v.Hi < 0
	if neg {
		var c uint64
		lo, c = bits.Add64(^lo, 1, 0)
		hi = ^hi + c
	}
	u := new(big.Int).SetUint64(hi)
	u.Lsh(u, 64)
	u.Or(u, new(big.Int).SetUint64(lo))
	if neg {
		u.Neg(u)
	}
	return Decimal{u: u, scale: v.Scale}
}

// ---- UUID ----

// UUID is a UUID's 16 bytes.
type UUID [16]byte

// String is the canonical 8-4-4-4-12 lowercase form.
func (u UUID) String() string {
	var b [36]byte
	hex.Encode(b[0:8], u[0:4])
	b[8] = '-'
	hex.Encode(b[9:13], u[4:6])
	b[13] = '-'
	hex.Encode(b[14:18], u[6:8])
	b[18] = '-'
	hex.Encode(b[19:23], u[8:10])
	b[23] = '-'
	hex.Encode(b[24:], u[10:])
	return string(b[:])
}

// ParseUUID reads the 8-4-4-4-12 form (either case).
func ParseUUID(s string) (UUID, error) {
	var u UUID
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return u, fmt.Errorf("imagedb: %q is not a UUID", s)
	}
	h := s[0:8] + s[9:13] + s[14:18] + s[19:23] + s[24:]
	if _, err := hex.Decode(u[:], []byte(h)); err != nil {
		return u, fmt.Errorf("imagedb: %q is not a UUID", s)
	}
	return u, nil
}

// Scan is database/sql's Scanner: from a UUID, its 16 bytes or its text.
func (u *UUID) Scan(src any) error {
	switch s := src.(type) {
	case UUID:
		*u = s
		return nil
	case []byte:
		if len(s) == 16 {
			copy(u[:], s)
			return nil
		}
		return u.Scan(string(s))
	case string:
		x, err := ParseUUID(s)
		if err == nil {
			*u = x
		}
		return err
	}
	return fmt.Errorf("imagedb: cannot scan %T into a UUID", src)
}

// ---- dates and times without a zone ----

// Date is a civil date (DATE: 0001-01-01 to 9999-12-31, the proleptic Gregorian calendar), no zone.
type Date struct {
	Year  int
	Month time.Month
	Day   int
}

// DateOf is t's date in t's location.
func DateOf(t time.Time) Date {
	y, m, d := t.Date()
	return Date{y, m, d}
}

// DateFromDays is the date days after 1970-01-01.
func DateFromDays(days int32) Date { return DateOf(time.Unix(int64(days)*86400, 0).UTC()) }

// Days is the days since 1970-01-01; refused for a date that is not one (2023-02-30) or outside years 1 to 9999.
func (d Date) Days() (int32, error) {
	t := time.Date(d.Year, d.Month, d.Day, 0, 0, 0, 0, time.UTC)
	if DateOf(t) != d || d.Year < 1 || d.Year > 9999 {
		return 0, fmt.Errorf("imagedb: %04d-%02d-%02d is not a date from 0001-01-01 to 9999-12-31", d.Year, int(d.Month), d.Day)
	}
	return int32(t.Unix() / 86400), nil
}

// In is the date's midnight in loc.
func (d Date) In(loc *time.Location) time.Time {
	return time.Date(d.Year, d.Month, d.Day, 0, 0, 0, 0, loc)
}

func (d Date) String() string { return fmt.Sprintf("%04d-%02d-%02d", d.Year, int(d.Month), d.Day) }

// TimeOfDay is a civil time (TIME: 00:00:00 to 23:59:59.999999), no zone.
type TimeOfDay struct {
	Hour, Minute, Second, Microsecond int
}

// TimeOfDayFromMicros is the time micros after midnight.
func TimeOfDayFromMicros(us int64) TimeOfDay {
	return TimeOfDay{int(us / 3600e6), int(us / 60e6 % 60), int(us / 1e6 % 60), int(us % 1e6)}
}

// Micros is the microseconds since midnight; refused for a field out of its range.
func (t TimeOfDay) Micros() (int64, error) {
	if t.Hour < 0 || t.Hour > 23 || t.Minute < 0 || t.Minute > 59 || t.Second < 0 || t.Second > 59 ||
		t.Microsecond < 0 || t.Microsecond > 999999 {
		return 0, fmt.Errorf("imagedb: %s is not a time of day", t.String())
	}
	return ((int64(t.Hour)*60+int64(t.Minute))*60+int64(t.Second))*1e6 + int64(t.Microsecond), nil
}

func (t TimeOfDay) String() string {
	s := fmt.Sprintf("%02d:%02d:%02d", t.Hour, t.Minute, t.Second)
	if t.Microsecond != 0 {
		s += fmt.Sprintf(".%06d", t.Microsecond)
	}
	return s
}

// DateTime is a TIMESTAMP: a civil date and time, no zone (0001-01-01 00:00 to 9999-12-31 23:59:59.999999).
type DateTime struct {
	Date Date
	Time TimeOfDay
}

// DateTimeOf is t's wall clock in t's location.
func DateTimeOf(t time.Time) DateTime {
	return DateTime{DateOf(t), TimeOfDay{t.Hour(), t.Minute(), t.Second(), t.Nanosecond() / 1000}}
}

// DateTimeFromMicros is the date and time micros after 1970-01-01 00:00.
func DateTimeFromMicros(us int64) DateTime { return DateTimeOf(time.UnixMicro(us).UTC()) }

// Micros is the microseconds since 1970-01-01 00:00 (no zone); refused for fields out of their range.
func (dt DateTime) Micros() (int64, error) {
	days, err := dt.Date.Days()
	if err != nil {
		return 0, err
	}
	us, err := dt.Time.Micros()
	if err != nil {
		return 0, err
	}
	return int64(days)*86400e6 + us, nil
}

// In is the date and time as a time.Time in loc.
func (dt DateTime) In(loc *time.Location) time.Time {
	return time.Date(dt.Date.Year, dt.Date.Month, dt.Date.Day, dt.Time.Hour, dt.Time.Minute, dt.Time.Second,
		dt.Time.Microsecond*1000, loc)
}

func (dt DateTime) String() string { return dt.Date.String() + " " + dt.Time.String() }

// Interval is an INTERVAL: months, days and microseconds, any triple (the engine keeps them apart: 1 mon is not 30 days).
type Interval struct {
	Months int32
	Days   int32
	Micros int64
}

func (iv Interval) String() string {
	return fmt.Sprintf("%d mons %d days %d us", iv.Months, iv.Days, iv.Micros)
}

// ---- parameters ----

// ToValue converts a Go value to the wire value a parameter carries, without loss or refused:
//
//	nil                                  a NULL of no type
//	TypedNull, a nil *T, sql.NullX{}      a NULL of T's type (sql.Null[T] too)
//	int, int8..int64, uint8..uint32      INT64; uint and uint64 INT64, past its range a DECIMAL of scale 0
//	float32, float64                     FLOAT64 (NaN and an infinity refused; -0 sent as 0, the engine's one zero)
//	bool, string                         BOOL, TEXT (strict UTF-8 without NUL; an ENUM's label is sent as TEXT)
//	[]byte                               BYTEA (a nil []byte a NULL BYTEA)
//	Decimal, *big.Int, a decomposer      DECIMAL (a big.Int at scale 0)
//	time.Time                            TIMESTAMPTZ (the instant; refused below a microsecond, never rounded)
//	DateTime, Date, TimeOfDay            TIMESTAMP, DATE, TIME
//	UUID, [16]byte                       UUID
//	Interval; time.Duration              INTERVAL (a Duration in whole microseconds)
//	wire.Value                           as it is
//	another driver.Valuer                its Value, converted
func ToValue(x any) (wire.Value, error) {
	v, err := toValue(x, 0)
	if err != nil {
		return v, err
	}
	if !wire.ValueOK(&v) {
		return v, fmt.Errorf("imagedb: a %s parameter outside its type's range", v.Type)
	}
	if v.Type == wire.TypeEnum && !v.Null {
		return v, errors.New("imagedb: an ENUM parameter is sent as TEXT (its label)")
	}
	return v, nil
}

var reflectBytes = reflect.TypeOf([]byte(nil))

func toValue(x any, depth int) (wire.Value, error) {
	if depth > 4 {
		return wire.Value{}, errors.New("imagedb: a parameter's Valuer nests too deep")
	}
	if rv := reflect.ValueOf(x); rv.Kind() == reflect.Pointer && rv.IsNil() { // a nil *T: a NULL of T's type
		return wire.Value{Null: true, Type: goType(rv.Type().Elem())}, nil
	}
	switch v := x.(type) {
	case nil:
		return wire.Value{Null: true}, nil
	case wire.Value:
		return v, nil
	case TypedNull:
		if v.Type > wire.TypeLast {
			return wire.Value{}, fmt.Errorf("imagedb: a NULL of %s", v.Type)
		}
		return wire.Value{Null: true, Type: v.Type}, nil
	case int64:
		return wire.Value{Type: wire.TypeInt64, I: v}, nil
	case int:
		return wire.Value{Type: wire.TypeInt64, I: int64(v)}, nil
	case int32:
		return wire.Value{Type: wire.TypeInt64, I: int64(v)}, nil
	case int16:
		return wire.Value{Type: wire.TypeInt64, I: int64(v)}, nil
	case int8:
		return wire.Value{Type: wire.TypeInt64, I: int64(v)}, nil
	case uint8:
		return wire.Value{Type: wire.TypeInt64, I: int64(v)}, nil
	case uint16:
		return wire.Value{Type: wire.TypeInt64, I: int64(v)}, nil
	case uint32:
		return wire.Value{Type: wire.TypeInt64, I: int64(v)}, nil
	case uint:
		return uintValue(uint64(v)), nil
	case uint64:
		return uintValue(v), nil
	case float64:
		return floatValue(v)
	case float32:
		return floatValue(float64(v))
	case bool:
		return wire.Value{Type: wire.TypeBool, I: int64(b2i(v))}, nil
	case string:
		if len(v) > wire.ValueMax || !wire.StringOK(v) {
			return wire.Value{}, errors.New("imagedb: a TEXT parameter is at most 65,535 bytes of UTF-8 without NUL")
		}
		return wire.Value{Type: wire.TypeText, S: []byte(v)}, nil
	case []byte:
		if v == nil {
			return wire.Value{Null: true, Type: wire.TypeBytea}, nil
		}
		if len(v) > wire.ValueMax {
			return wire.Value{}, errors.New("imagedb: a BYTEA parameter is at most 65,535 bytes")
		}
		return wire.Value{Type: wire.TypeBytea, S: v}, nil
	case Decimal:
		return v.toWire(), nil
	case *big.Int:
		if v == nil {
			return wire.Value{Null: true, Type: wire.TypeDecimal}, nil
		}
		d, err := NewDecimal(v, 0)
		if err != nil {
			return wire.Value{}, err
		}
		return d.toWire(), nil
	case time.Time:
		if v.Nanosecond()%1000 != 0 {
			return wire.Value{}, errors.New("imagedb: a time.Time below a microsecond: imagedb keeps microseconds " +
				"(t.Truncate(time.Microsecond) says which you want)")
		}
		if u := v.UTC(); u.Year() < 1 || u.Year() > 9999 {
			return wire.Value{}, errors.New("imagedb: a TIMESTAMPTZ is in years 1 to 9999")
		}
		return wire.Value{Type: wire.TypeTimestampTZ, I: v.UnixMicro()}, nil
	case DateTime:
		us, err := v.Micros()
		return wire.Value{Type: wire.TypeTimestamp, I: us}, err
	case Date:
		days, err := v.Days()
		return wire.Value{Type: wire.TypeDate, Day: days}, err
	case TimeOfDay:
		us, err := v.Micros()
		return wire.Value{Type: wire.TypeTime, I: us}, err
	case UUID:
		return wire.Value{Type: wire.TypeUUID, S: append([]byte(nil), v[:]...)}, nil
	case [16]byte:
		return wire.Value{Type: wire.TypeUUID, S: append([]byte(nil), v[:]...)}, nil
	case Interval:
		return wire.Value{Type: wire.TypeInterval, Mon: v.Months, Day: v.Days, I: v.Micros}, nil
	case time.Duration:
		if v%time.Microsecond != 0 {
			return wire.Value{}, errors.New("imagedb: a time.Duration below a microsecond (an INTERVAL keeps microseconds)")
		}
		return wire.Value{Type: wire.TypeInterval, I: int64(v / time.Microsecond)}, nil
	case decomposer:
		var d Decimal
		if err := d.Compose(v.Decompose(nil)); err != nil {
			return wire.Value{}, err
		}
		return d.toWire(), nil
	}
	rv := reflect.ValueOf(x)
	// database/sql's NullX and Null[T]: {V or the value's field, Valid}; not valid: a NULL of the value's type
	if rv.Kind() == reflect.Struct && rv.Type().PkgPath() == "database/sql" && rv.NumField() == 2 &&
		rv.Type().Field(1).Name == "Valid" && rv.Field(1).Kind() == reflect.Bool {
		if !rv.Field(1).Bool() {
			return wire.Value{Null: true, Type: goType(rv.Field(0).Type())}, nil
		}
		return toValue(rv.Field(0).Interface(), depth+1)
	}
	if rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			return wire.Value{Null: true, Type: goType(rv.Type().Elem())}, nil
		}
		return toValue(rv.Elem().Interface(), depth+1)
	}
	if vr, ok := x.(driver.Valuer); ok {
		y, err := vr.Value()
		if err != nil {
			return wire.Value{}, err
		}
		return toValue(y, depth+1)
	}
	switch rv.Kind() { // named types over the basic kinds
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return wire.Value{Type: wire.TypeInt64, I: rv.Int()}, nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return uintValue(rv.Uint()), nil
	case reflect.Float32, reflect.Float64:
		return floatValue(rv.Float())
	case reflect.Bool:
		return toValue(rv.Bool(), depth+1)
	case reflect.String:
		return toValue(rv.String(), depth+1)
	case reflect.Slice:
		if rv.Type().Elem().Kind() == reflect.Uint8 {
			return toValue(rv.Bytes(), depth+1)
		}
	}
	return wire.Value{}, fmt.Errorf("imagedb: a parameter of type %T has no wire type", x)
}

// goType is the wire type ToValue gives a Go type's values (a NULL of that type for a nil *T or an invalid sql.NullX):
// TypeNone where it has none.
func goType(t reflect.Type) Type {
	switch t {
	case reflect.TypeOf(Decimal{}), reflect.TypeOf((*big.Int)(nil)), reflect.TypeOf(big.Int{}):
		return TypeDecimal
	case reflect.TypeOf(time.Time{}):
		return TypeTimestampTZ
	case reflect.TypeOf(DateTime{}):
		return TypeTimestamp
	case reflect.TypeOf(Date{}):
		return TypeDate
	case reflect.TypeOf(TimeOfDay{}):
		return TypeTime
	case reflect.TypeOf(UUID{}), reflect.TypeOf([16]byte{}):
		return TypeUUID
	case reflect.TypeOf(Interval{}), reflect.TypeOf(time.Duration(0)):
		return TypeInterval
	}
	switch t.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16,
		reflect.Uint32, reflect.Uint64:
		return TypeInt64
	case reflect.Float32, reflect.Float64:
		return TypeFloat64
	case reflect.Bool:
		return TypeBool
	case reflect.String:
		return TypeText
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			return TypeBytea
		}
	case reflect.Pointer:
		return goType(t.Elem())
	case reflect.Struct:
		if t.PkgPath() == "database/sql" && t.NumField() == 2 && t.Field(1).Name == "Valid" {
			return goType(t.Field(0).Type)
		}
	}
	return TypeNone
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func uintValue(u uint64) wire.Value {
	if u <= math.MaxInt64 {
		return wire.Value{Type: wire.TypeInt64, I: int64(u)}
	}
	return wire.Value{Type: wire.TypeDecimal, Lo: u} // an integer past INT64: a DECIMAL of scale 0, as its literal
}

// floatValue: NaN and the infinities refused; -0 sent as 0, the one zero the engine keeps (its literal -0.0 stores 0), so
// a computed -0 binds as its literal would rather than failing. The codec itself (wire.ValueOK) refuses -0, as wire.c's.
func floatValue(f float64) (wire.Value, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return wire.Value{}, errors.New("imagedb: a FLOAT64 is finite (NaN and the infinities refused)")
	}
	if f == 0 {
		f = 0 // -0 to 0
	}
	return wire.Value{Type: wire.TypeFloat64, F: math.Float64bits(f)}, nil
}

// ---- results ----

// FromValue is a wire value's Go value: nil for a NULL (of any type); INT64 int64, FLOAT64 float64 (its exact bits),
// BOOL bool, TEXT and ENUM string, DECIMAL Decimal, TIMESTAMPTZ time.Time (UTC), TIMESTAMP DateTime, DATE Date, TIME
// TimeOfDay, UUID UUID, BYTEA []byte (a copy), INTERVAL Interval.
func FromValue(v *wire.Value) any {
	if v.Null {
		return nil
	}
	switch v.Type {
	case wire.TypeInt64:
		return v.I
	case wire.TypeFloat64:
		return math.Float64frombits(v.F)
	case wire.TypeBool:
		return v.I == 1
	case wire.TypeText, wire.TypeEnum:
		return string(v.S)
	case wire.TypeDecimal:
		return decimalFromWire(v)
	case wire.TypeTimestamp:
		return DateTimeFromMicros(v.I)
	case wire.TypeTimestampTZ:
		return time.UnixMicro(v.I).UTC()
	case wire.TypeDate:
		return DateFromDays(v.Day)
	case wire.TypeTime:
		return TimeOfDayFromMicros(v.I)
	case wire.TypeUUID:
		var u UUID
		copy(u[:], v.S)
		return u
	case wire.TypeBytea:
		return append([]byte{}, v.S...)
	case wire.TypeInterval:
		return Interval{Months: v.Mon, Days: v.Day, Micros: v.I}
	}
	return nil
}

// scanType is the Go type FromValue gives a column's non-NULL values.
func scanType(t Type) reflect.Type {
	switch t {
	case TypeInt64:
		return reflect.TypeOf(int64(0))
	case TypeFloat64:
		return reflect.TypeOf(float64(0))
	case TypeBool:
		return reflect.TypeOf(false)
	case TypeText, TypeEnum:
		return reflect.TypeOf("")
	case TypeDecimal:
		return reflect.TypeOf(Decimal{})
	case TypeTimestamp:
		return reflect.TypeOf(DateTime{})
	case TypeTimestampTZ:
		return reflect.TypeOf(time.Time{})
	case TypeDate:
		return reflect.TypeOf(Date{})
	case TypeTime:
		return reflect.TypeOf(TimeOfDay{})
	case TypeUUID:
		return reflect.TypeOf(UUID{})
	case TypeBytea:
		return reflectBytes
	case TypeInterval:
		return reflect.TypeOf(Interval{})
	}
	return reflect.TypeOf((*any)(nil)).Elem()
}
