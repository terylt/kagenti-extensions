package apiclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// An audit-record frame decodes as an audit record; a frame with no event
// name, or session-event, still decodes as a session event.
func TestParseSSE_RoutesFramesByEventName(t *testing.T) {
	stream := strings.Join([]string{
		": ok", "",
		"event: audit-record", "id: 1",
		`data: {"seq":7,"requestId":"1-abc","sessionId":"claude-1","record":{"class_uid":6003}}`, "",
		"event: session-event", "id: 2", `data: {"sessionId":"claude-1"}`, "",
		`data: {"sessionId":"bare"}`, "",
	}, "\n") + "\n"

	out := make(chan StreamEvent, 8)
	_ = parseSSE(context.Background(), strings.NewReader(stream), out)
	close(out)
	var got []StreamEvent
	for ev := range out {
		got = append(got, ev)
	}
	if len(got) != 3 {
		t.Fatalf("got %d messages, want 3: %+v", len(got), got)
	}
	a := got[0].Audit
	if a == nil || got[0].Event != nil || a.Seq != 7 || a.RequestID != "1-abc" || a.SessionID != "claude-1" ||
		string(a.Record) != `{"class_uid":6003}` {
		t.Errorf("audit message = %+v", got[0])
	}
	if got[1].Event == nil || got[1].Audit != nil || got[1].Event.SessionID != "claude-1" {
		t.Errorf("session-event message = %+v", got[1])
	}
	if got[2].Event == nil || got[2].Event.SessionID != "bare" {
		t.Errorf("unnamed frame = %+v", got[2])
	}
}

func TestGetAudit_SendsTheQueryAndDecodesThePage(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/audit" {
			http.NotFound(w, r)
			return
		}
		gotQuery = r.URL.RawQuery
		fmt.Fprint(w, `{"records":[{"seq":3,"sessionId":"s","record":{"a":1}}],"skipped":2}`)
	}))
	defer srv.Close()

	page, err := New(srv.URL).GetAudit(context.Background(), "s", 2, 10)
	if err != nil {
		t.Fatal(err)
	}
	if gotQuery != "after=2&limit=10&session=s" {
		t.Errorf("query = %q", gotQuery)
	}
	if len(page.Records) != 1 || page.Records[0].Seq != 3 || string(page.Records[0].Record) != `{"a":1}` || page.Skipped != 2 {
		t.Errorf("page = %+v", page)
	}
}

func TestGetAudit_NotFoundWhenTheServerHasNoAuditStore(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	if _, err := New(srv.URL).GetAudit(context.Background(), "", 0, 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}
