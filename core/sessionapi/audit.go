package sessionapi

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/rossoctl/cortex/core/audit"
)

// auditListDefault and auditListMax bound one GET /v1/audit page.
const (
	auditListDefault = 500
	auditListMax     = 5000
)

// WithAudit attaches the audit record store, which serves GET /v1/audit and
// adds `audit-record` events to GET /v1/events. Without it the endpoint
// returns 404 and the stream carries session events only.
func WithAudit(a *audit.Store) Option {
	return func(s *Server) { s.audit = a }
}

// handleAudit answers GET /v1/audit: stored audit records, oldest first.
//
//	?session=<id>  only records naming that cortex session
//	?after=<seq>   only records the store took after that one (paging)
//	?limit=N       at most N (default 500, max 5000)
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if s.audit == nil {
		http.NotFound(w, r)
		return
	}
	q := r.URL.Query()
	var after uint64
	if v := q.Get("after"); v != "" {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			http.Error(w, "after must be a non-negative integer", http.StatusBadRequest)
			return
		}
		after = n
	}
	limit := auditListDefault
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			http.Error(w, "limit must be a positive integer", http.StatusBadRequest)
			return
		}
		limit = min(n, auditListMax)
	}
	body := struct {
		Records []audit.Record `json:"records"`
		// Skipped counts lines in the records file that were not records.
		Skipped uint64 `json:"skipped"`
	}{
		Records: s.audit.List(strings.TrimSpace(q.Get("session")), after, limit),
		Skipped: s.audit.Skipped(),
	}
	payload, err := marshalAudit(body)
	if err != nil {
		slog.Debug("sessionapi: audit encode failed", "error", err)
		http.Error(w, "encode failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(payload)
}

// marshalAudit encodes v without HTML escaping. encoding/json compacts an
// embedded json.RawMessage, and with HTML escaping on it would also rewrite
// `<`, `>`, `&`, U+2028 and U+2029 inside the record's strings. The record
// is already compact, so with escaping off its bytes pass through unchanged.
func marshalAudit(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}
