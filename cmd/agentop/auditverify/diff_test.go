package auditverify

import (
	"bytes"
	"encoding/json"
	"testing"
)

// The demo's tamper: one deny flipped to an allow. Against the original, the one change is the
// action, named and shown both ways.
func TestChangesNameTheFlippedVerdict(t *testing.T) {
	records, _ := fixture(t)
	edited := bytes.Replace(records[1], []byte(`"action":"Denied"`), []byte(`"action":"Allowed"`), 1)
	got, err := Changes(records[1], edited)
	if err != nil {
		t.Fatal(err)
	}
	want := []Change{{Path: "action", Was: `"Denied"`, Now: `"Allowed"`}}
	if len(got) != 1 || got[0] != want[0] {
		t.Fatalf("changes = %+v, want %+v", got, want)
	}
}

// A ledger keeps the covered bytes, without the signature; comparing them with the full record
// must find nothing.
func TestTheSignatureIsNotAChange(t *testing.T) {
	records, _ := fixture(t)
	doc, err := decode(records[0])
	if err != nil {
		t.Fatal(err)
	}
	ledgerCopy, err := json.Marshal(covered(doc))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Changes(ledgerCopy, records[0])
	if err != nil || len(got) != 0 {
		t.Fatalf("changes = %+v, %v; want none", got, err)
	}
}

func TestChangesFindNestedAddedAndRemovedFields(t *testing.T) {
	was := []byte(`{"a":1,"gone":"x","list":[{"v":"p"},{"v":"q"}],"deep":{"k":1}}`)
	now := []byte(`{"a":1,"new":true,"list":[{"v":"p"},{"v":"r"}],"deep":{"k":2}}`)
	got, err := Changes(was, now)
	if err != nil {
		t.Fatal(err)
	}
	want := []Change{
		{Path: "deep.k", Was: "1", Now: "2"},
		{Path: "gone", Was: `"x"`, Now: ""},
		{Path: "list[1].v", Was: `"q"`, Now: `"r"`},
		{Path: "new", Was: "", Now: "true"},
	}
	if len(got) != len(want) {
		t.Fatalf("changes = %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("change %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// A record's fingerprint is the one the next record links to, and a ledger copy without the
// signature gives the same value: how a deleted record's ledger copy is shown to be the record.
func TestFingerprintMatchesTheNextRecordsLink(t *testing.T) {
	records, _ := fixture(t)
	fp, err := Fingerprint(records[1])
	if err != nil {
		t.Fatal(err)
	}
	if got := PrevFingerprint(records[2]); got != fp {
		t.Fatalf("next record links to %s, fingerprint is %s", got, fp)
	}
	doc, _ := decode(records[1])
	ledgerCopy, _ := json.Marshal(covered(doc))
	if got, _ := Fingerprint(ledgerCopy); got != fp {
		t.Fatalf("ledger copy fingerprint %s, record %s", got, fp)
	}
	if PrevFingerprint(records[0]) != "" {
		t.Error("the genesis record names a predecessor")
	}
}
