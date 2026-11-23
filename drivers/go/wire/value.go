package wire

import (
	"encoding/binary"
	"math/bits"
)

// The ranges of §4's table (wire.c: TS_MIN_US, TS_MAX_US; codec.h: IMDB_DATE_MIN/MAX, IMDB_TIME_MAX).
const (
	TimestampMin = -62135596800000000 // 0001-01-01 00:00:00
	TimestampMax = 253402300799999999 // 9999-12-31 23:59:59.999999
	DateMin      = -719162            // 0001-01-01, days since 1970-01-01
	DateMax      = 2932896            // 9999-12-31
	TimeMax      = 86399999999        // 23:59:59.999999, microseconds since midnight
	DecimalMax   = 38                 // digits and scale
)

// Value is one wire value: a type (1 to 13), or a NULL of a type (0 to 13). Only the fields of its type are read:
//   - INT64, TIMESTAMP, TIMESTAMPTZ, TIME: I; BOOL: I (0 or 1); FLOAT64: F (IEEE 754 binary64's bits)
//   - DECIMAL: Scale and the unscaled i128 Hi:Lo (two's complement, |v| < 10^38)
//   - DATE: Day (days since 1970-01-01); INTERVAL: Mon, Day, I (microseconds), any triple
//   - TEXT, BYTEA, ENUM (the label), UUID (16 bytes): S; a decoded value's S aliases the bytes it came in
type Value struct {
	Type  Type
	Null  bool
	I     int64
	F     uint64
	Mon   int32
	Day   int32
	Scale uint8
	Hi    int64
	Lo    uint64
	S     []byte
}

// utf8Valid is wire.c's utf8_valid (the engine's rule: no NUL, no overlong form, no surrogate, nothing past U+10FFFF),
// kept scalar and byte for byte the C one's; bad is the first byte of the first character that is not one.
func utf8Valid(s []byte) (ok bool, bad int) {
	i, n := 0, len(s)
	for i < n {
		c := s[i]
		if c >= 0x01 && c < 0x80 {
			i++
			continue
		}
		var need int
		lo, hi := byte(0x80), byte(0xBF)
		switch {
		case c >= 0xC2 && c <= 0xDF:
			need = 1
		case c == 0xE0:
			need, lo = 2, 0xA0
		case c >= 0xE1 && c <= 0xEC:
			need = 2
		case c == 0xED:
			need, hi = 2, 0x9F
		case c == 0xEE || c == 0xEF:
			need = 2
		case c == 0xF0:
			need, lo = 3, 0x90
		case c >= 0xF1 && c <= 0xF3:
			need = 3
		case c == 0xF4:
			need, hi = 3, 0x8F
		default: // NUL, C0, C1, F5..FF, a stray continuation
			return false, i
		}
		if need > n-i-1 || s[i+1] < lo || s[i+1] > hi {
			return false, i
		}
		for j := 2; j <= need; j++ {
			if s[i+j]&0xC0 != 0x80 {
				return false, i
			}
		}
		i += need + 1
	}
	return true, 0
}

// TextOK reports whether b is UTF-8 without NUL by the engine's rule.
func TextOK(b []byte) bool { ok, _ := utf8Valid(b); return ok }

// StringOK is TextOK for a string.
func StringOK(s string) bool { ok, _ := utf8Valid([]byte(s)); return ok }

// UTF8Fit is wire.c's imdbw_utf8_fit: the longest prefix of s, at most max bytes, that is UTF-8 without NUL (cut before
// the first byte that is not, never inside a character).
func UTF8Fit(s []byte, max int) int {
	k := len(s)
	if max < k {
		k = max
	}
	if k <= 0 {
		return 0
	}
	if ok, bad := utf8Valid(s[:k]); !ok {
		return bad
	}
	return k
}

// utf8Chars counts the characters of valid UTF-8: the bytes that begin one (wire.c's utf8_chars: code points).
func utf8Chars(s []byte) int {
	k := 0
	for _, c := range s {
		if c&0xC0 != 0x80 {
			k++
		}
	}
	return k
}

// pow10 holds 10^k as an unsigned 128-bit hi:lo, k 0 to 38.
var pow10 [DecimalMax + 1][2]uint64

func init() {
	hi, lo := uint64(0), uint64(1)
	for k := 0; k <= DecimalMax; k++ {
		pow10[k] = [2]uint64{hi, lo}
		h1, l1 := bits.Mul64(lo, 10)
		hi = hi*10 + h1
		lo = l1
	}
}

// Pow10 returns 10^k (0 <= k <= 38) as an unsigned 128-bit hi:lo.
func Pow10(k int) (hi, lo uint64) { return pow10[k][0], pow10[k][1] }

// DecimalFits reports whether the two's-complement i128 hi:lo is less than 10^digits in magnitude (wire.c's dec_in).
func DecimalFits(hi int64, lo uint64, digits int) bool {
	uh, ul := uint64(hi), lo
	if hi < 0 { // the magnitude; -2^127's is 2^127, past 10^38 either way
		var c uint64
		ul, c = bits.Add64(^ul, 1, 0)
		uh = ^uh + c
	}
	ph, pl := pow10[digits][0], pow10[digits][1]
	return uh < ph || (uh == ph && ul < pl)
}

// ValueOK is the value's own rules, its decoder's and its encoder's (wire.c's imdbw_value_ok).
func ValueOK(v *Value) bool {
	if v.Null {
		return v.Type <= TypeLast // a NULL of a type, or of none
	}
	switch v.Type {
	case TypeInt64, TypeInterval:
		return true
	case TypeFloat64:
		return (v.F>>52)&0x7ff != 0x7ff && v.F != 0x8000000000000000 // finite, not -0
	case TypeBool:
		return v.I == 0 || v.I == 1
	case TypeText:
		return len(v.S) <= ValueMax && TextOK(v.S)
	case TypeBytea:
		return len(v.S) <= ValueMax
	case TypeEnum:
		return len(v.S) <= LabelMax && TextOK(v.S)
	case TypeDecimal:
		return v.Scale <= DecimalMax && DecimalFits(v.Hi, v.Lo, DecimalMax)
	case TypeTimestamp, TypeTimestampTZ:
		return v.I >= TimestampMin && v.I <= TimestampMax
	case TypeDate:
		return v.Day >= DateMin && v.Day <= DateMax
	case TypeTime:
		return v.I >= 0 && v.I <= TimeMax
	case TypeUUID:
		return len(v.S) == 16
	}
	return false // no type: only a NULL has none
}

// valueSize is a valid value's bytes on the wire.
func valueSize(v *Value) int {
	if v.Null {
		return 1
	}
	switch v.Type {
	case TypeBool:
		return 2
	case TypeDate:
		return 5
	case TypeText, TypeBytea:
		return 5 + len(v.S)
	case TypeEnum:
		return 2 + len(v.S)
	case TypeDecimal:
		return 18
	case TypeUUID, TypeInterval:
		return 17
	}
	return 9 // INT64, FLOAT64, TIMESTAMP, TIMESTAMPTZ, TIME
}

// appendRaw writes a value whose rules the caller checked.
func appendRaw(b []byte, v *Value) []byte {
	if v.Null {
		return append(b, NullTag|byte(v.Type))
	}
	b = append(b, byte(v.Type))
	le := binary.LittleEndian
	switch v.Type {
	case TypeFloat64:
		b = le.AppendUint64(b, v.F)
	case TypeBool:
		b = append(b, byte(v.I))
	case TypeText, TypeBytea:
		b = le.AppendUint32(b, uint32(len(v.S)))
		b = append(b, v.S...)
	case TypeEnum:
		b = append(b, byte(len(v.S)))
		b = append(b, v.S...)
	case TypeDecimal:
		b = append(b, v.Scale)
		b = le.AppendUint64(b, v.Lo)
		b = le.AppendUint64(b, uint64(v.Hi))
	case TypeDate:
		b = le.AppendUint32(b, uint32(v.Day))
	case TypeUUID:
		b = append(b, v.S...)
	case TypeInterval:
		b = le.AppendUint32(b, uint32(v.Mon))
		b = le.AppendUint32(b, uint32(v.Day))
		b = le.AppendUint64(b, uint64(v.I))
	default: // INT64, TIMESTAMP, TIMESTAMPTZ, TIME
		b = le.AppendUint64(b, uint64(v.I))
	}
	return b
}

// AppendValue appends v's bytes, or refuses a value ValueOK refuses (nothing appended).
func AppendValue(b []byte, v *Value) ([]byte, error) {
	if !ValueOK(v) {
		return b, refused("a value outside its type's rules")
	}
	return appendRaw(b, v), nil
}

// DecodeValue reads one value at b[off:]: the value (its S aliasing b) and the offset past it. Strict as wire.c's
// imdbw_value_get: a length past its bound refused (CodeLimit) before its bytes are asked for.
func DecodeValue(b []byte, off int) (Value, int, error) {
	var v Value
	if off >= len(b) {
		return v, off, corrupt("a value cut short")
	}
	tag := b[off]
	off++
	if tag&NullTag != 0 {
		v.Null = true
		v.Type = Type(tag &^ NullTag)
		if v.Type > TypeLast {
			return v, off, corrupt("a NULL of a type the protocol does not define")
		}
		return v, off, nil
	}
	v.Type = Type(tag)
	left := len(b) - off
	le := binary.LittleEndian
	short := func() (Value, int, error) { return v, off, corrupt("a value cut short") }
	switch v.Type {
	case TypeInt64, TypeTimestamp, TypeTimestampTZ, TypeTime:
		if left < 8 {
			return short()
		}
		v.I = int64(le.Uint64(b[off:]))
		off += 8
	case TypeFloat64:
		if left < 8 {
			return short()
		}
		v.F = le.Uint64(b[off:])
		off += 8
	case TypeBool:
		if left < 1 {
			return short()
		}
		v.I = int64(b[off])
		off++
	case TypeText, TypeBytea, TypeEnum:
		var n, max, lb int
		if v.Type == TypeEnum {
			lb, max = 1, LabelMax
			if left < 1 {
				return short()
			}
			n = int(b[off])
		} else {
			lb, max = 4, ValueMax
			if left < 4 {
				return short()
			}
			n = int(le.Uint32(b[off:])) // u32: an int holds it on 64-bit
		}
		off += lb
		if n > max { // before its bytes are asked for
			return v, off, limitf("a value of %d bytes (at most %d)", n, max)
		}
		if len(b)-off < n {
			return short()
		}
		v.S = b[off : off+n : off+n]
		off += n
	case TypeDecimal:
		if left < 17 {
			return short()
		}
		v.Scale = b[off]
		v.Lo = le.Uint64(b[off+1:])
		v.Hi = int64(le.Uint64(b[off+9:]))
		off += 17
	case TypeDate:
		if left < 4 {
			return short()
		}
		v.Day = int32(le.Uint32(b[off:]))
		off += 4
	case TypeUUID:
		if left < 16 {
			return short()
		}
		v.S = b[off : off+16 : off+16]
		off += 16
	case TypeInterval:
		if left < 16 {
			return short()
		}
		v.Mon = int32(le.Uint32(b[off:]))
		v.Day = int32(le.Uint32(b[off+4:]))
		v.I = int64(le.Uint64(b[off+8:]))
		off += 16
	default:
		return v, off, corrupt("a value of a type the protocol does not define (a NULL's tag is 0x80 and its type)")
	}
	if !ValueOK(&v) {
		return v, off, corrupt("a value outside its type's rules")
	}
	return v, off, nil
}

// ValueEqual reports whether a and b have the same wire bytes (wire.c's imdbw_value_eq); invalid values are unequal.
func ValueEqual(a, b *Value) bool {
	x, e1 := AppendValue(nil, a)
	y, e2 := AppendValue(nil, b)
	return e1 == nil && e2 == nil && string(x) == string(y)
}
