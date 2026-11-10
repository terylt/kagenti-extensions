package auditverify

import (
	"bytes"
	"encoding/json"
	"math"
	"os"
	"strings"
	"testing"
)

// testdata/records.ndjson is three records (allow, deny, allow) the
// ocsf-audit file exporter wrote from inside cortex, chained and
// DSSE-signed under key id cortex-spike-1. The AID-EMIT-1 reference
// validator passes all three with signing-public-key.txt, a PEM public key
// named .txt because the repository ignores *.pem.
func fixture(t *testing.T) ([][]byte, Keys) {
	t.Helper()
	raw, err := os.ReadFile("testdata/records.ndjson")
	if err != nil {
		t.Fatal(err)
	}
	var records [][]byte
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
		records = append(records, line)
	}
	pemBytes, err := os.ReadFile("testdata/signing-public-key.txt")
	if err != nil {
		t.Fatal(err)
	}
	key, err := ParsePublicKeyPEM(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	return records, Keys{"cortex-spike-1": key}
}

func TestUntouchedRecordsVerify(t *testing.T) {
	records, keys := fixture(t)
	report := Verify(records, keys)
	wantLinks := []LinkState{LinkGenesis, LinkIntact, LinkIntact}
	for i, r := range report.Results {
		if r.Err != nil || !r.FingerprintOK || r.Signature != SignatureValid || r.Link != wantLinks[i] || r.Tampered() {
			t.Errorf("record %d: %+v", i, r)
		}
		if r.Stamp == nil || r.Stamp.StreamSeq != uint64(i) || r.Stamp.Epoch != 1792342541877693000 {
			t.Errorf("record %d stamp: %+v", i, r.Stamp)
		}
	}
	if len(report.Gaps) != 0 {
		t.Errorf("gaps: %+v", report.Gaps)
	}
}

// Flipping the deny to an allow breaks that record's fingerprint and
// signature, and the next record's link to it.
func TestAFlippedVerdictIsCaught(t *testing.T) {
	records, keys := fixture(t)
	records[1] = bytes.Replace(records[1], []byte(`"action":"Denied"`), []byte(`"action":"Allowed"`), 1)
	report := Verify(records, keys)

	edited := report.Results[1]
	if edited.FingerprintOK || edited.Signature != SignatureInvalid || !edited.Tampered() {
		t.Errorf("edited record: %+v", edited)
	}
	if next := report.Results[2]; next.Link != LinkBroken || !next.Tampered() {
		t.Errorf("record after the edit: %+v", next)
	}
	if first := report.Results[0]; first.Tampered() {
		t.Errorf("record before the edit: %+v", first)
	}
}

// Deleting a record leaves a stream gap and a missing predecessor; the
// records on either side still verify on their own.
func TestADeletedRecordIsAGap(t *testing.T) {
	records, keys := fixture(t)
	report := Verify([][]byte{records[0], records[2]}, keys)

	if after := report.Results[1]; after.Link != LinkMissing || after.Tampered() || after.Signature != SignatureValid {
		t.Errorf("record after the deletion: %+v", after)
	}
	want := []Gap{{Epoch: 1792342541877693000, StreamID: "cortex-spike:decision", From: 1, To: 1}}
	if len(report.Gaps) != 1 || report.Gaps[0] != want[0] {
		t.Errorf("gaps = %+v, want %+v", report.Gaps, want)
	}
}

// A missing head (the stream does not start at 0) is a gap too.
func TestAMissingHeadIsAGap(t *testing.T) {
	records, keys := fixture(t)
	report := Verify(records[1:], keys)
	if len(report.Gaps) != 1 || report.Gaps[0].From != 0 || report.Gaps[0].To != 0 {
		t.Errorf("gaps = %+v", report.Gaps)
	}
}

// The sink can write concurrent records out of chain order, so arrival
// order must not matter.
func TestOrderDoesNotMatter(t *testing.T) {
	records, keys := fixture(t)
	report := Verify([][]byte{records[2], records[0], records[1]}, keys)
	for _, r := range report.Results {
		if r.Tampered() || r.Link == LinkMissing {
			t.Errorf("record %d: %+v", r.Index, r)
		}
	}
	if len(report.Gaps) != 0 {
		t.Errorf("gaps: %+v", report.Gaps)
	}
}

func TestAnUnknownKeyIsNotATamper(t *testing.T) {
	records, _ := fixture(t)
	report := Verify(records, Keys{})
	for _, r := range report.Results {
		if r.Signature != SignatureUnknownKey || !r.FingerprintOK || r.Tampered() {
			t.Errorf("record %d: %+v", r.Index, r)
		}
	}
}

func TestAnUnsealedRecordIsNotTampered(t *testing.T) {
	report := Verify([][]byte{[]byte(`{"class_uid":6003}`)}, nil)
	if r := report.Results[0]; r.Link != LinkUnchained || r.Tampered() {
		t.Errorf("unsealed record: %+v", r)
	}
}

func TestMalformedRecordsAreReportedNotFatal(t *testing.T) {
	records, keys := fixture(t)
	report := Verify([][]byte{[]byte("not json"), records[0], []byte("null")}, keys)
	if report.Results[0].Err == nil || report.Results[2].Err == nil {
		t.Errorf("malformed records: %+v / %+v", report.Results[0], report.Results[2])
	}
	if report.Results[1].Err != nil || report.Results[1].Tampered() {
		t.Errorf("good record: %+v", report.Results[1])
	}
}

// RFC 8785 Appendix B: the ES6 form of each IEEE 754 double.
func TestES6NumberMatchesRFC8785AppendixB(t *testing.T) {
	cases := []struct {
		bits uint64
		want string
	}{
		{0x0000000000000000, "0"},
		{0x8000000000000000, "0"},
		{0x0000000000000001, "5e-324"},
		{0x8000000000000001, "-5e-324"},
		{0x7fefffffffffffff, "1.7976931348623157e+308"},
		{0xffefffffffffffff, "-1.7976931348623157e+308"},
		{0x4340000000000000, "9007199254740992"},
		{0xc340000000000000, "-9007199254740992"},
		{0x4430000000000000, "295147905179352830000"},
		{0x44b52d02c7e14af5, "9.999999999999997e+22"},
		{0x44b52d02c7e14af6, "1e+23"},
		{0x44b52d02c7e14af7, "1.0000000000000001e+23"},
		{0x444b1ae4d6e2ef4e, "999999999999999700000"},
		{0x444b1ae4d6e2ef4f, "999999999999999900000"},
		{0x444b1ae4d6e2ef50, "1e+21"},
		{0x3eb0c6f7a0b5ed8c, "9.999999999999997e-7"},
		{0x3eb0c6f7a0b5ed8d, "0.000001"},
		{0x41b3de4355555553, "333333333.3333332"},
		{0x41b3de4355555554, "333333333.33333325"},
		{0x41b3de4355555555, "333333333.3333333"},
		{0x41b3de4355555556, "333333333.3333334"},
		{0x41b3de4355555557, "333333333.33333343"},
		{0xbecbf647612f3696, "-0.0000033333333333333333"},
		{0x43143ff3c1cb0959, "1424953923781206.2"},
	}
	for _, c := range cases {
		if got := es6Number(math.Float64frombits(c.bits)); got != c.want {
			t.Errorf("%#016x: got %s, want %s", c.bits, got, c.want)
		}
	}
}

// Integers are written as given, including ones a double cannot hold;
// other numbers take the ES6 form; keys sort by UTF-16 code units; strings
// escape only what the sink's encoder escapes.
func TestCanonicalFormMatchesTheSink(t *testing.T) {
	in := `{"b":1792342541877693123,"a":[2.0,0.1,1e21,-0,12],` +
		`"😀":"emoji","דּ":"after surrogate",` +
		`"s":"<&> \u0001\t\"\\/é"}`
	doc, err := decode([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := canonicalize(&buf, doc); err != nil {
		t.Fatal(err)
	}
	want := `{"a":[2,0.1,1e+21,0,12],"b":1792342541877693123,` +
		`"s":"<&>` + " " + `\u0001\t\"\\/é",` +
		`"😀":"emoji","דּ":"after surrogate"}`
	if got := buf.String(); got != want {
		t.Errorf("canonical form\n got: %s\nwant: %s", got, want)
	}
}

// The fixture's signatures verifying already shows the canonical bytes
// match the sink's for real records; this pins the number handling that a
// strict JCS library would get wrong.
func TestAnIntegerBeyondDoublePrecisionKeepsItsDigits(t *testing.T) {
	got, err := canonicalNumber("1792342541877693123")
	if err != nil || got != "1792342541877693123" {
		t.Fatalf("got %q, %v", got, err)
	}
	var f float64
	if err := json.Unmarshal([]byte("1792342541877693123"), &f); err != nil {
		t.Fatal(err)
	}
	if strings.HasSuffix(es6Number(f), "123") {
		t.Fatal("a double kept digits it cannot hold; the test premise is wrong")
	}
}
