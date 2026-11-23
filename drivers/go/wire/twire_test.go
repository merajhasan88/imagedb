package wire

// TestTWireSource holds this package's copies of the contract's vectors to tests/unit/t_wire.c itself: every value
// vector, every refused value, every length past its bound, the three pinned SCRAM exchanges and every one-line
// body(...) check of t_wire_bounds (with its verdict) that t_wire.c holds is in the tables here, and nothing here claims a
// vector t_wire.c lacks. A change to t_wire.c's vectors fails this test until the copies follow.
//
// The file: IMDB_T_WIRE (run_tests.sh sets it: the repository's tests/unit/t_wire.c by default), else
// ../../../tests/unit/t_wire.c from this package's directory; without either it is skipped.

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func norm(h string) string { return strings.ReplaceAll(h, " ", "") }

// block is the text of t_wire.c from the line that begins with start to the next line "};" or "}" at its indentation.
func block(t *testing.T, src, start, end string) string {
	t.Helper()
	i := strings.Index(src, start)
	if i < 0 {
		t.Fatalf("t_wire.c: %q not found", start)
	}
	j := strings.Index(src[i:], end)
	if j < 0 {
		t.Fatalf("t_wire.c: the end of %q not found", start)
	}
	return src[i : i+j]
}

func multiset(xs []string) map[string]int {
	m := map[string]int{}
	for _, x := range xs {
		m[norm(x)]++
	}
	return m
}

func sameSet(t *testing.T, what string, theirs, ours []string) {
	t.Helper()
	a, b := multiset(theirs), multiset(ours)
	for k, n := range a {
		if b[k] != n {
			t.Errorf("%s: t_wire.c has %q %d times, the copy %d", what, k, n, b[k])
		}
	}
	for k, n := range b {
		if a[k] != n {
			t.Errorf("%s: the copy has %q %d times, t_wire.c %d", what, k, n, a[k])
		}
	}
}

func TestTWireSource(t *testing.T) {
	path := os.Getenv("IMDB_T_WIRE")
	if path == "" {
		path = "../../../tests/unit/t_wire.c"
		if _, err := os.Stat(path); err != nil {
			t.Skip("t_wire.c not found (IMDB_T_WIRE names it; run_tests.sh sets it)")
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("t_wire.c: %v", err)
	}
	src := string(b)

	// the value vectors (kVecs)
	vecRe := regexp.MustCompile(`\}, "([0-9a-f ]+)"\},`)
	var theirs, ours []string
	for _, m := range vecRe.FindAllStringSubmatch(block(t, src, "static const vec kVecs[] = {", "\n};"), -1) {
		theirs = append(theirs, m[1])
	}
	for _, v := range kVecs {
		ours = append(ours, v.hex)
	}
	if len(theirs) < 20 {
		t.Fatalf("t_wire.c's kVecs: %d vectors read", len(theirs))
	}
	sameSet(t, "value vectors", theirs, ours)

	// the refused values and the lengths past their bounds
	strRe := regexp.MustCompile(`"([0-9a-f ]*)"`)
	theirs = nil
	for _, m := range strRe.FindAllStringSubmatch(block(t, src, "static const char *const refused[] = {", "\n    };"), -1) {
		theirs = append(theirs, m[1])
	}
	sameSet(t, "refused values", theirs, refusedVecs)
	theirs = nil
	for _, m := range strRe.FindAllStringSubmatch(block(t, src, "static const char *const limit[] = {", "};"), -1) {
		theirs = append(theirs, m[1])
	}
	sameSet(t, "lengths past their bounds", theirs, limitVecs)

	// the pinned SCRAM exchanges: every 64-digit hex string of t_wire_scram
	pinRe := regexp.MustCompile(`"([0-9a-f]{64})"`)
	theirs = nil
	for _, m := range pinRe.FindAllStringSubmatch(block(t, src, "static void t_wire_scram(void)", "\n}\n"), -1) {
		theirs = append(theirs, m[1])
	}
	ours = nil
	for _, p := range pinnedScram {
		ours = append(ours, p.proof, p.ssig)
	}
	sameSet(t, "pinned SCRAM exchanges", theirs, ours)

	// t_wire_bounds' one-line body(...) checks and its counts[] cases, each in the table with its verdict
	byName := map[string]FrameType{}
	for ft, n := range frameNames {
		byName[n] = ft
	}
	mine := map[string]int{}
	for _, c := range boundsTable() {
		mine[c.ty.String()+":"+norm(c.hex)] = c.want
	}
	bounds := block(t, src, "static void t_wire_bounds(void)", "\n}\n")
	bodyRe := regexp.MustCompile(`CHECK\(body\(IMDBW_([A-Z_]+), "([0-9a-f ]*)", NULL\) (==|!=) (0|IMDB_ERR_LIMIT)\);`)
	n := 0
	for _, m := range bodyRe.FindAllStringSubmatch(bounds, -1) {
		ft, ok := byName[m[1]]
		if !ok {
			t.Fatalf("t_wire.c: frame %s", m[1])
		}
		want := -1
		switch {
		case m[3] == "==" && m[4] == "0":
			want = 0
		case m[3] == "==" && m[4] == "IMDB_ERR_LIMIT":
			want = CodeLimit
		}
		got, ok := mine[ft.String()+":"+norm(m[2])]
		if !ok || (want == -1 && got == 0) || (want != -1 && got != want) {
			t.Errorf("t_wire_bounds: body(%s, %q) %s %s: the copy has %v (present %v)", m[1], m[2], m[3], m[4], got, ok)
		}
		n++
	}
	countRe := regexp.MustCompile(`\{IMDBW_([A-Z_]+), "([0-9a-f ]+)"\},`)
	for _, m := range countRe.FindAllStringSubmatch(block(t, bounds, "} counts[] = {", "};"), -1) {
		if got, ok := mine[byName[m[1]].String()+":"+norm(m[2])]; !ok || got == 0 {
			t.Errorf("t_wire_bounds' counts: %s %q not refused in the copy", m[1], m[2])
		}
		n++
	}
	if n < 80 {
		t.Fatalf("t_wire_bounds: %d checks read", n)
	}
	t.Logf("t_wire.c (%s): %d value vectors, %d refused, %d limits, %d pinned hashes, %d body checks matched", path,
		len(kVecs), len(refusedVecs), len(limitVecs), 2*len(pinnedScram), n)
}
