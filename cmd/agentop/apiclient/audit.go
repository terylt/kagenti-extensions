package apiclient

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
	"time"
)

// AuditRecord is one signed audit record from GET /v1/audit or an
// `audit-record` stream event. Record holds the record's bytes as the
// policy engine wrote them; agentop verifies them itself rather than
// trusting cortex's word for it (see cmd/agentop/auditverify).
type AuditRecord struct {
	Seq        uint64          `json:"seq"`
	ReceivedAt time.Time       `json:"receivedAt"`
	RequestID  string          `json:"requestId,omitempty"`
	SessionID  string          `json:"sessionId,omitempty"`
	Record     json.RawMessage `json:"record"`
}

// AuditPage is one GET /v1/audit response.
type AuditPage struct {
	Records []AuditRecord `json:"records"`
	// Skipped counts lines in the records file that were not records.
	Skipped uint64 `json:"skipped"`
}

// GetAudit fetches stored audit records, oldest first: those naming
// sessionID when it is set, those after the store's seq after, at most
// limit (the server's default when 0). Returns ErrNotFound when the server
// does not serve audit records (session.audit off, or an older cortex).
func (c *Client) GetAudit(ctx context.Context, sessionID string, after uint64, limit int) (*AuditPage, error) {
	q := url.Values{}
	if sessionID != "" {
		q.Set("session", sessionID)
	}
	if after > 0 {
		q.Set("after", strconv.FormatUint(after, 10))
	}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	path := "/v1/audit"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	var page AuditPage
	if err := c.getJSON(ctx, path, &page); err != nil {
		return nil, err
	}
	return &page, nil
}
