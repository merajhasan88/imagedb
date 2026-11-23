package wire

// The codec against the contract's own bytes: tests/unit/t_wire.c's value vectors, refusals, pre-auth messages, the
// three pinned SCRAM exchanges (docs/n1-design.md §4) and its body bounds, copied here with the line ranges they come
// from (t_wire.c as of 2026-11-19), never values derived by this driver.

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/rand"
	"strings"
	"testing"
	"unicode/utf8"
)

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatalf("a malformed vector %q: %v", s, err)
	}
	return b
}

func code(err error) int {
	var we *Error
	if errors.As(err, &we) {
		return we.Code
	}
	if err != nil {
		return -1
	}
	return 0
}

var kUUID = []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}

// t_wire.c lines 55-84 (kVecs): the contract, each type's bytes
var kVecs = []struct {
	v   Value
	hex string
}{
	{Value{Null: true}, "80"},
	{Value{Null: true, Type: TypeInt64}, "81"},
	{Value{Null: true, Type: TypeDecimal}, "85"},
	{Value{Null: true, Type: TypeEnum}, "8d"},
	{Value{Type: TypeInt64, I: -2}, "01 feffffffffffffff"},
	{Value{Type: TypeInt64, I: -1 << 63}, "01 0000000000000080"},
	{Value{Type: TypeFloat64, F: 0x3ff8000000000000}, "02 000000000000f83f"},
	{Value{Type: TypeFloat64, F: 0}, "02 0000000000000000"},
	{Value{Type: TypeBool, I: 1}, "03 01"},
	{Value{Type: TypeBool, I: 0}, "03 00"},
	{Value{Type: TypeText, S: []byte("h\xc3\xa9")}, "04 03000000 68c3a9"},
	{Value{Type: TypeText, S: []byte("")}, "04 00000000"},
	{Value{Type: TypeDecimal, Scale: 2, Hi: -1, Lo: uint64(0xffffffffffffcfc7)}, "05 02 c7cfffffffffffffffffffffffffffff"},
	{Value{Type: TypeDecimal}, "05 00 00000000000000000000000000000000"},
	{Value{Type: TypeTimestamp, I: 1}, "06 0100000000000000"},
	{Value{Type: TypeTimestamp, I: -62135596800000000}, "06 0040d400014023ff"},
	{Value{Type: TypeTimestampTZ, I: -1}, "07 ffffffffffffffff"},
	{Value{Type: TypeTimestampTZ, I: 253402300799999999}, "07 ff5f73cc0c448403"},
	{Value{Type: TypeDate, Day: -719162}, "08 c606f5ff"},
	{Value{Type: TypeDate, Day: 2932896}, "08 a0c02c00"},
	{Value{Type: TypeTime, I: 0}, "09 0000000000000000"},
	{Value{Type: TypeTime, I: 86399999999}, "09 ff5fd71d14000000"},
	{Value{Type: TypeUUID, S: kUUID}, "0a 000102030405060708090a0b0c0d0e0f"},
	{Value{Type: TypeBytea, S: []byte{0x00, 0xff}}, "0b 02000000 00ff"},
	{Value{Type: TypeInterval, Mon: 1, Day: -2, I: 3}, "0c 01000000 feffffff 0300000000000000"},
	{Value{Type: TypeInterval, Mon: -1 << 31, Day: 1<<31 - 1, I: -1 << 63}, "0c 00000080 ffffff7f 0000000000000080"},
	{Value{Type: TypeEnum, S: []byte("a")}, "0d 01 61"},
	{Value{Type: TypeEnum, S: []byte("")}, "0d 00"},
}

func decodeOne(b []byte) (Value, error) {
	v, off, err := DecodeValue(b, 0)
	if err == nil && off != len(b) {
		err = corrupt("bytes past the value")
	}
	return v, err
}

func TestValueVectors(t *testing.T) {
	for k, vec := range kVecs {
		want := unhex(t, vec.hex)
		got, err := AppendValue(nil, &vec.v)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("vector %d: encoded %x (%v), want %x", k, got, err, want)
		}
		v, err := decodeOne(want)
		if err != nil || !ValueEqual(&v, &vec.v) {
			t.Fatalf("vector %d: decoded %+v (%v)", k, v, err)
		}
		for cut := 0; cut < len(want); cut++ { // every prefix refused
			if _, err := decodeOne(want[:cut]); err == nil {
				t.Fatalf("vector %d: a prefix of %d bytes taken", k, cut)
			}
		}
	}
	// t_wire.c lines 105-116: DECIMAL's range, 10^38 - 1 and its negation taken, 10^38 and -10^38 refused, scale 39 refused
	ph, pl := Pow10(38)
	lim := [2]uint64{ph, pl}
	sub1 := func(x [2]uint64) [2]uint64 {
		if x[1] == 0 {
			return [2]uint64{x[0] - 1, ^uint64(0)}
		}
		return [2]uint64{x[0], x[1] - 1}
	}
	neg := func(x [2]uint64) [2]uint64 {
		lo := ^x[1] + 1
		hi := ^x[0]
		if lo == 0 {
			hi++
		}
		return [2]uint64{hi, lo}
	}
	for k, d := range [][2]uint64{sub1(lim), neg(sub1(lim)), lim, neg(lim)} {
		x := make([]byte, 18)
		x[0], x[1] = byte(TypeDecimal), 38
		binary.LittleEndian.PutUint64(x[2:], d[1])
		binary.LittleEndian.PutUint64(x[10:], d[0])
		if _, err := decodeOne(x); (err == nil) != (k < 2) {
			t.Fatalf("DECIMAL range case %d: %v", k, err)
		}
		x[1] = 39
		if _, err := decodeOne(x); err == nil {
			t.Fatalf("DECIMAL scale 39 taken (case %d)", k)
		}
	}
}

// t_wire.c lines 122-144 (refused) and 153 (limit: a length past its bound, refused before its bytes)
var (
	refusedVecs = []string{"03 02", "02 000000000000f07f", "02 000000000000f0ff", "02 010000000000f87f",
		"02 0000000000000080", "06 ff3fd400014023ff", "07 006073cc0c448403", "09 ffffffffffffffff", "09 0060d71d14000000",
		"08 c506f5ff", "08 a1c02c00", "04 01000000 ff", "04 01000000 00", "04 02000000 c0af", "0d 01 c3", "0d 01 00", "0e",
		"00", "8e", "ff", ""}
	limitVecs = []string{"04 00000100", "0b 00000100", "0d 40"}
)

func TestValueRefused(t *testing.T) {
	for _, h := range refusedVecs {
		if _, err := decodeOne(unhex(t, h)); err == nil {
			t.Fatalf("taken: %s", h)
		}
	}
	for _, h := range limitVecs {
		if _, err := decodeOne(unhex(t, h)); code(err) != CodeLimit {
			t.Fatalf("%s: %v, want a limit", h, err)
		}
	}
	// lines 161-175: the encoder refuses what the decoder would, nothing written
	big := make([]byte, 65536)
	for k, v := range []Value{
		{Type: TypeBool, I: 2}, {Type: TypeFloat64, F: 0x8000000000000000}, {Type: TypeText, S: []byte{0xff}},
		{Type: TypeText, S: big}, {Type: TypeEnum, S: []byte("0123456789012345678901234567890123456789012345678901234567890123")},
		{Type: TypeDecimal, Scale: 39}, {Type: TypeDate, Day: 2932897}, {Type: TypeTimestamp, I: 1<<63 - 1},
		{Type: TypeUUID, S: kUUID[:15]}, {Type: 14}, {Type: TypeNone}, {Type: 14, Null: true},
	} {
		b, err := AppendValue(nil, &v)
		if err == nil || len(b) != 0 || ValueOK(&v) {
			t.Fatalf("encoder case %d taken", k)
		}
	}
}

func TestUTF8(t *testing.T) {
	// t_wire.c lines 188-197
	s := []byte("ab\xc3\xa9" + "c\xe2\x82\xac")
	for _, c := range []struct{ n, max, want int }{{8, 100, 8}, {8, 8, 8}, {8, 7, 5}, {8, 6, 5}, {8, 5, 5}, {8, 3, 2}, {8, 0, 0}} {
		if got := UTF8Fit(s[:c.n], c.max); got != c.want {
			t.Fatalf("UTF8Fit(%d, %d) = %d, want %d", c.n, c.max, got, c.want)
		}
	}
	if UTF8Fit([]byte("ab\xffcd"), 5) != 2 || UTF8Fit([]byte("ab\x00cd"), 5) != 2 {
		t.Fatal("UTF8Fit before a bad byte")
	}
	// the validator against Go's own (unicode/utf8: no overlong, no surrogate, nothing past U+10FFFF) and no NUL, on
	// bytes drawn as t_wire.c lines 210-219 draw them
	pick := []byte{0x00, 0x41, 0x7f, 0x80, 0x8f, 0x90, 0x9f, 0xa0, 0xbf, 0xc0, 0xc1, 0xc2, 0xdf, 0xe0, 0xe1, 0xec, 0xed,
		0xee, 0xef, 0xf0, 0xf1, 0xf3, 0xf4, 0xf5, 0xff}
	rng := rand.New(rand.NewSource(1))
	for round := 0; round < 200000; round++ {
		x := make([]byte, 1+rng.Intn(12))
		for i := range x {
			if rng.Intn(4) != 0 {
				x[i] = pick[rng.Intn(len(pick))]
			} else {
				x[i] = byte(rng.Intn(256))
			}
		}
		want := utf8.Valid(x) && bytes.IndexByte(x, 0) < 0
		if TextOK(x) != want {
			t.Fatalf("%x: ours %v, Go's %v", x, !want, want)
		}
		if k := UTF8Fit(x, len(x)); k > 0 && !(utf8.Valid(x[:k]) && bytes.IndexByte(x[:k], 0) < 0) {
			t.Fatalf("UTF8Fit(%x) = %d: not a valid prefix", x, k)
		}
	}
}

func TestPreauth(t *testing.T) {
	h := Hello{Version: 1, User: "alice"}
	rand.New(rand.NewSource(2)).Read(h.Nonce[:])
	hb, err := h.Encode()
	if err != nil || !bytes.HasPrefix(hb, []byte("IMDBWIR1\x01\x00\x00\x00\x00\x00\x00\x00alice")) { // t_wire.c line 230
		t.Fatalf("hello %x %v", hb, err)
	}
	g, err := DecodeHello(hb)
	if err != nil || g.User != "alice" || g.Nonce != h.Nonce || g.Flags != 0 {
		t.Fatalf("hello back: %+v %v", g, err)
	}
	took, refusedN := 0, 0
	for i := range hb { // lines 234-249: a flip a decoder takes encodes back to itself
		for _, f := range []byte{0x01, 0x80, 0xff} {
			x := bytes.Clone(hb)
			x[i] ^= f
			if g, err := DecodeHello(x); err == nil {
				again, err := g.Encode()
				if err != nil || !bytes.Equal(again, x) {
					t.Fatalf("hello flip %d taken but not its bytes", i)
				}
				took++
			} else {
				refusedN++
			}
		}
	}
	if took < 32*3+1 || refusedN < 16*3 {
		t.Fatalf("hello flips: %d taken, %d refused", took, refusedN)
	}
	for fl := uint32(0); fl < 5; fl++ { // lines 250-257
		y := bytes.Clone(hb)
		y[12] = byte(fl)
		g, err := DecodeHello(y)
		if fl <= 2 && (err != nil || uint32(g.Flags) != fl) || fl > 2 && code(err) != CodeCorrupt {
			t.Fatalf("flags %d: %v", fl, err)
		}
	}
	x := bytes.Clone(hb) // lines 259-278
	x[8] = 2
	if _, err := DecodeHello(x); code(err) != CodeUnsupported || !strings.Contains(err.Error(), "version 2") {
		t.Fatalf("version 2: %v", err)
	}
	x = bytes.Clone(hb)
	x[7] = '2'
	if _, err := DecodeHello(x); code(err) != CodeUnsupported || !strings.Contains(err.Error(), "IMDBWIR2") {
		t.Fatalf("IMDBWIR2: %v", err)
	}
	x[7] = '0'
	if _, err := DecodeHello(x); code(err) != CodeCorrupt {
		t.Fatalf("IMDBWIR0: %v", err)
	}
	for _, mut := range []func([]byte){func(b []byte) { b[0] = 'X' }, func(b []byte) { b[8] = 0 }, func(b []byte) { b[12] = 3 }} {
		x = bytes.Clone(hb)
		mut(x)
		if _, err := DecodeHello(x); code(err) != CodeCorrupt {
			t.Fatalf("a damaged hello: %v", err)
		}
	}
	// lines 280-295: the role name, 1 to 63 bytes of UTF-8, NUL-padded
	x = bytes.Clone(hb)
	clear(x[16:80])
	if _, err := DecodeHello(x); err == nil {
		t.Fatal("an empty name taken")
	}
	for i := 16; i < 80; i++ {
		x[i] = 'a'
	}
	if _, err := DecodeHello(x); err == nil {
		t.Fatal("64 bytes taken")
	}
	x[16+63] = 0
	if g, err := DecodeHello(x); err != nil || len(g.User) != 63 {
		t.Fatalf("63 bytes: %v", err)
	}
	clear(x[16:80])
	x[16], x[18] = 'a', 'b'
	if _, err := DecodeHello(x); err == nil {
		t.Fatal("a byte past the NUL taken")
	}
	x[18], x[16] = 0, 0xff
	if _, err := DecodeHello(x); err == nil {
		t.Fatal("a name not UTF-8 taken")
	}
	if !UserOK("\xc3\xa9") || UserOK("") || UserOK("\xc3") {
		t.Fatal("UserOK")
	}
	// lines 298-312: the head every version keeps
	if v, err := DecodePreauthHead(hb); err != nil || v != 1 {
		t.Fatal("head")
	}
	x = bytes.Clone(hb[:12])
	binary.LittleEndian.PutUint32(x[8:], 7)
	if v, err := DecodePreauthHead(x); err != nil || v != 7 {
		t.Fatal("head of version 7")
	}
	binary.LittleEndian.PutUint32(x[8:], 0)
	if _, err := DecodePreauthHead(x); code(err) != CodeCorrupt {
		t.Fatal("head of version 0")
	}
	binary.LittleEndian.PutUint32(x[8:], 1)
	x[7] = '2'
	if _, err := DecodePreauthHead(x); code(err) != CodeUnsupported {
		t.Fatal("IMDBWIR2's head")
	}
	x[0] = 'X'
	if _, err := DecodePreauthHead(x); code(err) != CodeCorrupt {
		t.Fatal("another magic's head")
	}
	// lines 314-326: the encoder refuses what the decoder would
	for _, hh := range []Hello{{Version: 2, User: "a"}, {Version: 1, Flags: 3, User: "a"}, {Version: 1}, {Version: 1, User: "\xc3"}} {
		if _, err := hh.Encode(); err == nil {
			t.Fatalf("hello %+v encoded", hh)
		}
	}
	if b, err := (&Hello{Version: 1, Flags: BindingEndpoint, User: "a"}).Encode(); err != nil || b[12] != 2 {
		t.Fatal("hello of flags 2")
	}

	// lines 328-372: the challenge
	c := Challenge{Version: 1, Salt: make([]byte, 16), Iter: 4096}
	rand.New(rand.NewSource(3)).Read(c.Salt)
	rand.New(rand.NewSource(4)).Read(c.Nonce[:])
	cb, err := c.Encode()
	if err != nil {
		t.Fatal(err)
	}
	d, err := DecodeChallenge(cb)
	if err != nil || !bytes.Equal(d.Salt, c.Salt) || d.Iter != 4096 || d.Nonce != c.Nonce {
		t.Fatalf("challenge back: %v", err)
	}
	took, refusedN = 0, 0
	for i := range cb {
		for _, f := range []byte{0x01, 0x80, 0xff} {
			y := bytes.Clone(cb)
			y[i] ^= f
			if d, err := DecodeChallenge(y); err == nil {
				again, err := d.Encode()
				if err != nil || !bytes.Equal(again, y) {
					t.Fatalf("challenge flip %d taken but not its bytes", i)
				}
				took++
			} else {
				refusedN++
			}
		}
	}
	if took < (16+32)*3 || refusedN < (48+7)*3 {
		t.Fatalf("challenge flips: %d taken, %d refused", took, refusedN)
	}
	for _, sc := range []struct {
		sl   int
		iter uint32
		ok   bool
	}{{7, 4096, false}, {8, 4096, true}, {64, 4096, true}, {65, 4096, false}, {16, 999, false}, {16, 1000, true},
		{16, 1000000, true}, {16, 1000001, false}} {
		ch := c
		ch.Salt = make([]byte, sc.sl)
		ch.Iter = sc.iter
		y, err := ch.Encode()
		if (err == nil) != sc.ok {
			t.Fatalf("challenge encode %+v: %v", sc, err)
		}
		if !sc.ok { // the same bytes made by hand: the decoder refuses them too
			y = bytes.Clone(cb)
			y[12] = byte(sc.sl)
			binary.LittleEndian.PutUint32(y[13+64:], sc.iter)
		}
		if _, err := DecodeChallenge(y); (err == nil) != sc.ok {
			t.Fatalf("challenge decode %+v: %v", sc, err)
		}
	}
	y := bytes.Clone(cb)
	y[13+16] = 1 // a byte in the salt's padding
	if _, err := DecodeChallenge(y); err == nil {
		t.Fatal("salt padding taken")
	}

	// lines 374-397: the verdict
	vd := Verdict{}
	rand.New(rand.NewSource(5)).Read(vd.Sig[:])
	vb, _ := vd.Encode()
	if ve, err := DecodeVerdict(vb); err != nil || ve.Sig != vd.Sig || ve.Code != 0 {
		t.Fatal("verdict back")
	}
	vb[0] = 1
	if _, err := DecodeVerdict(vb); err == nil {
		t.Fatal("a refusal with a signature taken")
	}
	vd.Code = 1
	if _, err := vd.Encode(); err == nil {
		t.Fatal("a refusal with a signature encoded")
	}
	vd.Sig = [32]byte{}
	vb, err = vd.Encode()
	if err != nil {
		t.Fatal(err)
	}
	vb[0] = 2
	if ve, err := DecodeVerdict(vb); err != nil || ve.Code != VerdictBinding {
		t.Fatal("verdict 2")
	}
	vb[4] = 1
	if _, err := DecodeVerdict(vb); err == nil {
		t.Fatal("verdict 2 with a signature taken")
	}
	vb[4], vb[0] = 0, 3
	if _, err := DecodeVerdict(vb); err == nil {
		t.Fatal("verdict 3 taken")
	}
}

// pinnedScram: §4's three pinned exchanges (docs/n1-design.md lines 93-104; t_wire.c lines 444-457): user "alice",
// client nonce 32 x 01, salt 16 x 03, 4,096 iterations, server nonce 32 x 02, password "pencil"
var pinnedScram = []struct {
	name        string
	ep          Endpoint
	flags       Binding
	bind        byte
	proof, ssig string
}{
	{"TCP, the exporter", EndpointTCP, BindingExporter, 0x04,
		"28562c1bef99b0a917ecb28c1b32c22930f154f92c134b13fee7a64e8deb733e",
		"5d3ef834c39e6c429d1f4e27993ba451a8b8e35322af9055abc1dd40e88ad322"},
	{"TCP, tls-server-end-point", EndpointTCP, BindingEndpoint, 0x05,
		"1065f5e038b75f2671d831f5bd5d29f56d22a787f260db523bb986ef7c53f486",
		"28fef60553090aae9b5f184bfc0cfb455e58261131da359f525a59f4dfaa9904"},
	{"the socket", EndpointUnix, BindingNone, 0x00,
		"5ee7e7bd402f0c91e2399a84c3d544763bace50b44ea82a780e57130bb5405a7",
		"82c9d498cc5fa830d26b29740244ecf4f343962f302a647150e9d74ea7588027"},
}

// TestScramPinned: the pinned exchanges, byte for byte (t_wire.c lines 417-471).
func TestScramPinned(t *testing.T) {
	h := Hello{Version: 1, Flags: BindingExporter, User: "alice"}
	for i := range h.Nonce {
		h.Nonce[i] = 0x01
	}
	c := Challenge{Version: 1, Salt: bytes.Repeat([]byte{0x03}, 16), Iter: 4096}
	for i := range c.Nonce {
		c.Nonce[i] = 0x02
	}
	cb, err := c.Encode()
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range pinnedScram {
		h2 := h
		h2.Flags = x.flags
		hb, err := h2.Encode()
		if err != nil || hb[12] != byte(x.flags) {
			t.Fatal(err)
		}
		var bind [32]byte
		for i := range bind {
			bind[i] = x.bind
		}
		am := AuthMessage(x.ep, hb, cb, &bind)
		// the AuthMessage laid out by hand (t_wire.c lines 429-434)
		want := append([]byte("IMDBWIR1-SCRAM"), byte(x.ep))
		want = append(append(append(want, hb...), cb...), bind[:]...)
		if len(am) != AuthMsgLen || !bytes.Equal(am, want) {
			t.Fatalf("%s: the AuthMessage", x.name)
		}
		proof, ssig, err := ScramClient("pencil", &c, am)
		if err != nil || hex.EncodeToString(proof[:]) != x.proof || hex.EncodeToString(ssig[:]) != x.ssig {
			t.Fatalf("%s: proof %x sig %x (%v)", x.name, proof, ssig, err)
		}
		// the server's side, from the verifier CREATE ROLE makes of the password and salt
		stored, skey, err := ScramVerifier("pencil", c.Salt, 4096)
		if err != nil {
			t.Fatal(err)
		}
		if ok, sig := ScramServer(&stored, &skey, am, &proof); !ok || sig != ssig {
			t.Fatalf("%s: the server refuses the proof", x.name)
		}
		for bit := 0; bit < 256; bit++ { // any bit of the proof off: refused
			p2 := proof
			p2[bit/8] ^= 1 << (bit % 8)
			if ok, _ := ScramServer(&stored, &skey, am, &p2); ok {
				t.Fatalf("%s: a proof off by bit %d taken", x.name, bit)
			}
		}
		for i := range am { // any byte of the AuthMessage another: refused (every byte is bound)
			am2 := bytes.Clone(am)
			am2[i] ^= 0x20
			if ok, _ := ScramServer(&stored, &skey, am2, &proof); ok {
				t.Fatalf("%s: the AuthMessage's byte %d not bound", x.name, i)
			}
		}
	}
	// t_wire.c lines 472-482: a proof over a hello whose type byte alone differs is refused
	hb, _ := h.Encode()
	var bind [32]byte
	for i := range bind {
		bind[i] = 0x04
	}
	proof, _, _ := ScramClient("pencil", &c, AuthMessage(EndpointTCP, hb, cb, &bind))
	stored, skey, _ := ScramVerifier("pencil", c.Salt, 4096)
	for fl := byte(0); fl <= 2; fl++ {
		hb2 := bytes.Clone(hb)
		hb2[12] = fl
		ok, _ := ScramServer(&stored, &skey, AuthMessage(EndpointTCP, hb2, cb, &bind), &proof)
		if ok != (fl == 1) {
			t.Fatalf("type byte %d: %v", fl, ok)
		}
	}
	// lines 530-541: a password CREATE ROLE would refuse, and a challenge its decoder would
	am := AuthMessage(EndpointTCP, hb, cb, &bind)
	c.Iter = 1000
	for _, pw := range []string{"", "a\x7f", "a\x1f", "\xc3\xa9", strings.Repeat("a", 1025)} {
		if _, _, err := ScramClient(pw, &c, am); err == nil {
			t.Fatalf("password %q taken", pw)
		}
	}
	if _, _, err := ScramClient(strings.Repeat("a", 1024), &c, am); err != nil {
		t.Fatal("1,024 bytes refused")
	}
	c.Iter = 999
	if _, _, err := ScramClient("pencil", &c, am); err == nil {
		t.Fatal("999 iterations taken")
	}
}
