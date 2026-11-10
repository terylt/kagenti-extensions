package ledger_test

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	"github.com/rossoctl/cortex/cmd/agentop/auditverify"
	"github.com/rossoctl/cortex/cmd/agentop/ledger"
)

// Against a real ledger, after the CPEX adapter has shipped a records file into it:
//
//	AGENTOP_LEDGER_TEST_ADDR=127.0.0.1:19292 \
//	AGENTOP_LEDGER_TEST_RECORDS=/path/to/records.ndjson go test ./ledger/ -run Live
//
// Every record's receipt must carry the fingerprint agentop recomputes from the record, and the
// ledger must verify each receipt's proof and its own chain. Skipped without the address.
func TestLiveLedgerReceiptsMatchRecomputedFingerprints(t *testing.T) {
	addr := os.Getenv("AGENTOP_LEDGER_TEST_ADDR")
	if addr == "" {
		t.Skip("AGENTOP_LEDGER_TEST_ADDR not set")
	}
	path := os.Getenv("AGENTOP_LEDGER_TEST_RECORDS")
	if path == "" {
		path = "../auditverify/testdata/records.ndjson"
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var records [][]byte
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
		records = append(records, line)
	}
	report := auditverify.Verify(records, nil)

	c, err := ledger.Dial(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	snap, err := c.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range report.Results {
		e, ok := snap.ByUID[r.UID]
		if !ok {
			t.Errorf("record %s has no receipt", r.UID)
			continue
		}
		if e.InputHash != r.Fingerprint {
			t.Errorf("record %s: ledger input_hash %s, recomputed fingerprint %s", r.UID, e.InputHash, r.Fingerprint)
		}
		if got := snap.ByStamp[ledger.Stamp{Epoch: r.Stamp.Epoch, StreamID: r.Stamp.StreamID, StreamSeq: r.Stamp.StreamSeq}]; got.UID != r.UID {
			t.Errorf("record %s is not found by its stamp", r.UID)
		}
		p, err := c.VerifyProof(ctx, e)
		if err != nil || !p.Valid {
			t.Errorf("record %s: proof %+v, %v", r.UID, p, err)
		}
		t.Logf("%s  position %d  action %s  proof valid", r.UID, e.Position, e.Action)
	}
	for typ, chain := range snap.Chains {
		if !chain.Valid {
			t.Errorf("ledger chain %s: %+v", typ, chain)
		}
		t.Logf("chain %s: valid, %d entries checked", typ, chain.Checked)
	}
}
