package sessionapi

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rossoctl/cortex/core/audit"
)

// auditRecord is a record whose strings hold every character Go's HTML-safe
// encoder would rewrite, so a test can tell if the bytes changed in transit.
func auditRecord(requestID, sessionID string) string {
	return `{"ai_agent":{"instance_uid":"` + sessionID + `"},"status_detail":"a<b&c>d` +
		" " + `","unmapped":{"cmf.request.request_id":"` + requestID + `"}}`
}

func newAuditServer(t *testing.T) (string, *audit.Store) {
	t.Helper()
	a := audit.New(0)
	t.Cleanup(a.Close)
	ts, _ := newTestServer(t, WithAudit(a))
	return ts.URL, a
}

func getAudit(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func TestHandleAudit_NotFoundWithoutAStore(t *testing.T) {
	ts, _ := newTestServer(t)
	if code, _ := getAudit(t, ts.URL+"/v1/audit"); code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", code)
	}
}

func TestHandleAudit_ServesRecordBytesUnchanged(t *testing.T) {
	url, a := newAuditServer(t)
	raw := auditRecord("1-abc", "claude-1")
	a.Append(audit.Record{RequestID: "1-abc", SessionID: "claude-1", Record: json.RawMessage(raw)})

	code, body := getAudit(t, url+"/v1/audit")
	if code != http.StatusOK {
		t.Fatalf("status = %d: %s", code, body)
	}
	if !strings.Contains(body, `"record":`+raw) {
		t.Fatalf("record bytes changed in the response:\n%s\nwant to contain\n%s", body, raw)
	}
	var parsed struct {
		Records []audit.Record `json:"records"`
	}
	if err := json.Unmarshal([]byte(body), &parsed); err != nil || len(parsed.Records) != 1 ||
		parsed.Records[0].RequestID != "1-abc" || parsed.Records[0].SessionID != "claude-1" {
		t.Fatalf("parsed = %+v, %v", parsed, err)
	}
}

func TestHandleAudit_FiltersAndPages(t *testing.T) {
	url, a := newAuditServer(t)
	for _, sess := range []string{"a", "b", "a"} {
		a.Append(audit.Record{SessionID: sess, Record: json.RawMessage(auditRecord("r", sess))})
	}
	var body struct {
		Records []audit.Record `json:"records"`
	}
	_, raw := getAudit(t, url+"/v1/audit?session=a&after=1&limit=10")
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Records) != 1 || body.Records[0].Seq != 3 {
		t.Fatalf("records = %+v", body.Records)
	}
	for _, bad := range []string{"?after=-1", "?after=x", "?limit=0", "?limit=x"} {
		if code, _ := getAudit(t, url+"/v1/audit"+bad); code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", bad, code)
		}
	}
}

func TestHandleStream_DeliversAuditRecords(t *testing.T) {
	url, a := newAuditServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", url+"/v1/events?session=claude-1", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 8192), 4<<20)
	waitForLine(t, sc, ":", "initial comment", 2*time.Second)

	// Another session's record is filtered out; this session's arrives.
	a.Append(audit.Record{SessionID: "other", Record: json.RawMessage(auditRecord("r0", "other"))})
	raw := auditRecord("r1", "claude-1")
	a.Append(audit.Record{RequestID: "r1", SessionID: "claude-1", Record: json.RawMessage(raw)})

	if !scanUntil(t, sc, "event: audit-record", 2*time.Second) {
		t.Fatal("event: audit-record never arrived")
	}
	data := scanUntilPrefix(t, sc, "data: ", 2*time.Second)
	if !strings.Contains(data, `"record":`+raw) || strings.Contains(data, `"r0"`) {
		t.Fatalf("data = %s", data)
	}
}
