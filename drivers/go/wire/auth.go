package wire

import (
	"bytes"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
)

// UserOK reports whether u is a role name a hello takes: 1 to 63 bytes of UTF-8 without NUL.
func UserOK(u string) bool { return len(u) >= 1 && len(u) < UserField && StringOK(u) }

// PasswordOK reports whether pw is a password as CREATE ROLE takes one: 1 to 1,024 bytes of printable ASCII (no
// SASLprep in imagedb yet).
func PasswordOK(pw string) bool {
	if len(pw) < 1 || len(pw) > PasswordMax {
		return false
	}
	for i := 0; i < len(pw); i++ {
		if pw[i] < 0x20 || pw[i] > 0x7e {
			return false
		}
	}
	return true
}

func zeros(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// laterMagic is util.c's imdb_later_magic for "IMDBWIR1": the same letters and a larger trailing number.
func laterMagic(m []byte) bool {
	return len(m) >= 8 && string(m[:7]) == Magic[:7] && m[7] > '1' && m[7] <= '9'
}

func unsupportedf(format string, a ...any) error {
	return &Error{Code: CodeUnsupported, Msg: fmt.Sprintf(format, a...)}
}

// DecodePreauthHead reads the 12 bytes every pre-auth message begins with: any version (a server answers a hello of a
// version it does not speak with its own head and a close), a later magic refused by name, version 0 and another magic
// as damage.
func DecodePreauthHead(b []byte) (uint32, error) {
	if len(b) < PreauthHead {
		return 0, corrupt("a pre-auth head cut short")
	}
	ver := binary.LittleEndian.Uint32(b[8:])
	if string(b[:8]) != Magic {
		if laterMagic(b[:8]) {
			return ver, unsupportedf("%s, a later protocol, which this driver does not speak", string(b[:8]))
		}
		return ver, corrupt("not imagedb's protocol")
	}
	if ver < 1 {
		return ver, corrupt("protocol version 0")
	}
	return ver, nil
}

// magicVersion is a full message's head: version 1 alone (a later one by name).
func magicVersion(b []byte) error {
	ver, err := DecodePreauthHead(b)
	if err != nil {
		return err
	}
	if ver > Version {
		return unsupportedf("protocol version %d, a later one, which this driver (version %d) does not speak", ver, Version)
	}
	if ver != Version {
		return corrupt("an unknown protocol version")
	}
	return nil
}

// Hello is the client's first message (112 bytes).
type Hello struct {
	Version uint32
	Flags   Binding // the channel binding's type
	User    string
	Nonce   [NonceLen]byte
}

// Encode is the hello's bytes, or a refusal of what its decoder would refuse.
func (h *Hello) Encode() ([]byte, error) {
	if h.Version != Version || h.Flags > BindingEndpoint || !UserOK(h.User) {
		return nil, refused("a hello: version 1, a binding type 0 to 2, a role name of 1 to 63 bytes of UTF-8")
	}
	out := make([]byte, HelloLen)
	copy(out, Magic)
	binary.LittleEndian.PutUint32(out[8:], h.Version)
	binary.LittleEndian.PutUint32(out[12:], uint32(h.Flags))
	copy(out[16:], h.User)
	copy(out[16+UserField:], h.Nonce[:])
	return out, nil
}

// DecodeHello is wire.c's imdbw_hello_get.
func DecodeHello(b []byte) (Hello, error) {
	var h Hello
	if len(b) != HelloLen {
		return h, corrupt("a hello of another length")
	}
	if err := magicVersion(b); err != nil {
		return h, err
	}
	h.Version = Version
	h.Flags = Binding(binary.LittleEndian.Uint32(b[12:]))
	if h.Flags > BindingEndpoint {
		return h, corrupt("a hello with flags no version defines (a binding type but 0, 1, 2)")
	}
	u := b[16 : 16+UserField]
	n := bytes.IndexByte(u, 0)
	if n < 0 || !UserOK(string(u[:n])) || !zeros(u[n:]) {
		return h, corrupt("a hello's role name is not 1 to 63 bytes of UTF-8, NUL-padded")
	}
	h.User = string(u[:n])
	copy(h.Nonce[:], b[16+UserField:])
	return h, nil
}

// Challenge is the server's answer to a hello (120 bytes).
type Challenge struct {
	Version uint32
	Salt    []byte // 8 to 64 bytes
	Iter    uint32 // 1,000 to 1,000,000
	Nonce   [NonceLen]byte
}

func (c *Challenge) ok() bool {
	return c.Version == Version && len(c.Salt) >= ScramSaltMin && len(c.Salt) <= SaltField &&
		c.Iter >= ScramIterMin && c.Iter <= ScramIterMax
}

// Encode is the challenge's bytes (the offline fake server's and the tests').
func (c *Challenge) Encode() ([]byte, error) {
	if !c.ok() {
		return nil, refused("a challenge: a salt of 8 to 64 bytes, 1,000 to 1,000,000 iterations")
	}
	out := make([]byte, ChallengeLen)
	copy(out, Magic)
	binary.LittleEndian.PutUint32(out[8:], c.Version)
	out[12] = byte(len(c.Salt))
	copy(out[13:], c.Salt)
	binary.LittleEndian.PutUint32(out[13+SaltField:], c.Iter)
	copy(out[17+SaltField:], c.Nonce[:])
	return out, nil // then 7 zeros
}

// DecodeChallenge is wire.c's imdbw_challenge_get.
func DecodeChallenge(b []byte) (Challenge, error) {
	var c Challenge
	if len(b) != ChallengeLen {
		return c, corrupt("a challenge of another length")
	}
	if err := magicVersion(b); err != nil {
		return c, err
	}
	c.Version = Version
	sl := int(b[12])
	salt := b[13 : 13+SaltField]
	c.Iter = binary.LittleEndian.Uint32(b[13+SaltField:])
	copy(c.Nonce[:], b[17+SaltField:])
	pad := b[17+SaltField+NonceLen:]
	if sl < ScramSaltMin || sl > SaltField || c.Iter < ScramIterMin || c.Iter > ScramIterMax || !zeros(salt[sl:]) {
		return c, corrupt("a challenge's salt is not 8 to 64 bytes, zero-padded, or its iterations not 1,000 to 1,000,000")
	}
	if !zeros(pad) {
		return c, corrupt("a challenge's padding is not zero")
	}
	c.Salt = bytes.Clone(salt[:sl])
	return c, nil
}

// Verdict is the server's last pre-auth message (36 bytes).
type Verdict struct {
	Code uint32
	Sig  [KeyLen]byte // the server's signature; zeros when refused
}

func (v *Verdict) ok() bool {
	return v.Code == VerdictOK || ((v.Code == VerdictRefused || v.Code == VerdictBinding) && zeros(v.Sig[:]))
}

// Encode is the verdict's bytes.
func (v *Verdict) Encode() ([]byte, error) {
	if !v.ok() {
		return nil, refused("a verdict: accepted, or a refusal without a signature")
	}
	out := binary.LittleEndian.AppendUint32(nil, v.Code)
	return append(out, v.Sig[:]...), nil
}

// DecodeVerdict is wire.c's imdbw_verdict_get.
func DecodeVerdict(b []byte) (Verdict, error) {
	var v Verdict
	if len(b) != VerdictLen {
		return v, corrupt("a verdict of another length")
	}
	v.Code = binary.LittleEndian.Uint32(b)
	copy(v.Sig[:], b[4:])
	if !v.ok() {
		return v, corrupt("a verdict neither accepted nor refused, or a refusal carrying a signature")
	}
	return v, nil
}

// AuthMessage is what both sides HMAC: "IMDBWIR1-SCRAM" | endpoint | the hello's 112 bytes | the challenge's 120 |
// binding[32] (the hello's type's value: the exporter's 32 bytes, the certificate's SHA-256, or zeros on the socket).
func AuthMessage(ep Endpoint, hello, challenge []byte, binding *[KeyLen]byte) []byte {
	am := make([]byte, 0, AuthMsgLen)
	am = append(am, "IMDBWIR1-SCRAM"...)
	am = append(am, byte(ep))
	am = append(am, hello...)
	am = append(am, challenge...)
	return append(am, binding[:]...)
}

func hmac32(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

// keys is RFC 5802's ClientKey and ServerKey from the password (PBKDF2-HMAC-SHA-256 of its bytes).
func keys(pw string, salt []byte, iter uint32) (ck, sk []byte, err error) {
	sp, err := pbkdf2.Key(sha256.New, pw, salt, int(iter), KeyLen)
	if err != nil {
		return nil, nil, err
	}
	ck = hmac32(sp, []byte("Client Key"))
	sk = hmac32(sp, []byte("Server Key"))
	clear(sp)
	return ck, sk, nil
}

// ScramClient is the client's side (wire.c's imdbw_scram_client): the proof it sends and the server's signature it
// expects, or a refusal of a password CREATE ROLE would refuse or a challenge its decoder would.
func ScramClient(pw string, c *Challenge, am []byte) (proof, serverSig [KeyLen]byte, err error) {
	if !PasswordOK(pw) || !c.ok() || len(am) != AuthMsgLen {
		return proof, serverSig, refused("a password of 1 to 1,024 printable ASCII bytes, a valid challenge")
	}
	ck, sk, err := keys(pw, c.Salt, c.Iter)
	if err != nil {
		return proof, serverSig, err
	}
	stored := sha256.Sum256(ck)
	cs := hmac32(stored[:], am)
	for i := range proof {
		proof[i] = ck[i] ^ cs[i]
	}
	copy(serverSig[:], hmac32(sk, am))
	clear(ck)
	clear(sk)
	clear(stored[:])
	clear(cs)
	return proof, serverSig, nil
}

// ScramVerifier is a verifier's StoredKey and ServerKey from a password (the fake server's, as CREATE ROLE makes one).
func ScramVerifier(pw string, salt []byte, iter uint32) (stored, serverKey [KeyLen]byte, err error) {
	ck, sk, err := keys(pw, salt, iter)
	if err != nil {
		return stored, serverKey, err
	}
	stored = sha256.Sum256(ck)
	copy(serverKey[:], sk)
	clear(ck)
	clear(sk)
	return stored, serverKey, nil
}

// ScramServer is the server's side (wire.c's imdbw_scram_server): whether the proof is the password's (compared in
// constant time), and the server's signature either way.
func ScramServer(stored, serverKey *[KeyLen]byte, am []byte, proof *[KeyLen]byte) (bool, [KeyLen]byte) {
	var sig [KeyLen]byte
	cs := hmac32(stored[:], am)
	ck := make([]byte, KeyLen)
	for i := range ck {
		ck[i] = proof[i] ^ cs[i]
	}
	h := sha256.Sum256(ck)
	ok := subtle.ConstantTimeCompare(h[:], stored[:]) == 1
	copy(sig[:], hmac32(serverKey[:], am))
	return ok, sig
}
