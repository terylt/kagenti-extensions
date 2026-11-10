package auditverify_test

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rossoctl/cortex/cmd/agentop/apiclient"
	"github.com/rossoctl/cortex/cmd/agentop/auditverify"
	"github.com/rossoctl/cortex/core/audit"
	"github.com/rossoctl/cortex/core/session"
	"github.com/rossoctl/cortex/core/sessionapi"
)

// The whole read path: the sink's file, cortex's tailer and store, the
// session API, agentop's client, and the verifier. The records still
// verify at the end, so no hop changed a byte the signatures cover.
func TestRecordsSurviveTheReadPathAndStillVerify(t *testing.T) {
	src, err := os.ReadFile("testdata/records.ndjson")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "records.ndjson")
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}

	store := audit.New(0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go store.Follow(ctx, path)
	defer store.Close()

	sessions := session.New(time.Minute, 100, 0)
	defer sessions.Close()
	srv := httptest.NewServer(sessionapi.New(":0", sessions, sessionapi.WithAudit(store)).Server().Handler)
	defer srv.Close()

	var page *apiclient.AuditPage
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if page, err = apiclient.New(srv.URL).GetAudit(ctx, "", 0, 0); err == nil && len(page.Records) == 3 {
			break
		}
	}
	if err != nil || page == nil || len(page.Records) != 3 {
		t.Fatalf("page = %+v, err = %v", page, err)
	}

	pemBytes, err := os.ReadFile("testdata/signing-public-key.txt")
	if err != nil {
		t.Fatal(err)
	}
	key, err := auditverify.ParsePublicKeyPEM(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	var records [][]byte
	for _, r := range page.Records {
		records = append(records, r.Record)
	}
	report := auditverify.Verify(records, auditverify.Keys{"cortex-spike-1": key})
	for _, r := range report.Results {
		if r.Tampered() || r.Signature != auditverify.SignatureValid || r.Err != nil {
			t.Errorf("record %d after the read path: %+v", r.Index, r)
		}
	}
	if len(report.Gaps) != 0 {
		t.Errorf("gaps: %+v", report.Gaps)
	}
}
