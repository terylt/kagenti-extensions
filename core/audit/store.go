// Package audit holds the signed OCSF audit records the policy engine's
// ocsf-audit sink writes, so the session API can serve them to agentop.
//
// The sink writes each record to an append-only NDJSON file through its
// file exporter. The store follows that file by name and keeps each record's
// bytes exactly as written. It reads two fields to index a record, the
// cortex request id and session id, and nothing else: it does not verify a
// record. Verification is agentop's job, so that cortex never vouches for
// its own audit trail.
//
// The file is the durable trail. The store is a bounded window onto it for
// display, and DELETE /v1/sessions does not touch either.
package audit

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultMaxRecords is how many records the store keeps when the caller
// does not say. Older records leave the window, not the file.
const DefaultMaxRecords = 10000

// subscriberChanBuf matches the session store's per-subscriber buffer.
const subscriberChanBuf = 64

// Record is one audit record and what the store learned about it.
type Record struct {
	// Seq is the store's own position for the record, from 1, for paging
	// with ?after=. It is not the record's stream_seq.
	Seq        uint64    `json:"seq"`
	ReceivedAt time.Time `json:"receivedAt"`
	// RequestID is the cortex request id the record names
	// (unmapped."cmf.request.request_id"), which joins it to the session
	// event for the same request.
	RequestID string `json:"requestId,omitempty"`
	// SessionID is the cortex session the record names
	// (ai_agent.instance_uid). Empty when cortex did not resolve the session.
	SessionID string `json:"sessionId,omitempty"`
	// Record is the record exactly as the sink wrote it.
	Record json.RawMessage `json:"record"`
}

// Subscription receives every record appended after it was taken.
type Subscription struct {
	C <-chan Record
	// Reset receives when a mirroring store (see Mirror) drops its records
	// because the file changed under it. Pending signals coalesce into one.
	Reset <-chan struct{}
	ch    chan Record
	reset chan struct{}
	drops atomic.Uint64
	once  sync.Once
}

// Drops is how many records this subscriber missed because its buffer was
// full.
func (s *Subscription) Drops() uint64 { return s.drops.Load() }

// Store is a bounded, in-memory window of audit records with fan-out to
// live subscribers.
type Store struct {
	mu      sync.RWMutex
	records []Record
	max     int
	next    uint64
	subs    map[*Subscription]struct{}
	closed  bool
	skipped atomic.Uint64
	now     func() time.Time
	// generation counts resets, so a reader can tell the records it holds
	// came from a file that has since changed.
	generation atomic.Uint64
}

// New returns a store keeping at most maxRecords (DefaultMaxRecords when 0
// or less).
func New(maxRecords int) *Store {
	if maxRecords <= 0 {
		maxRecords = DefaultMaxRecords
	}
	return &Store{max: maxRecords, subs: map[*Subscription]struct{}{}, now: time.Now}
}

// Follow tails the records file at path into the store until ctx is done.
// Run it on its own goroutine.
func (s *Store) Follow(ctx context.Context, path string) {
	newTailer(path, s.appendLine, s.skip).run(ctx)
}

// Mirror is Follow for a viewer: the store holds what the file holds now.
// When the file is replaced, truncated or rewritten in place, the store drops
// its records, counts a new Generation, signals every subscription's Reset
// and reads the file again from the start. Follow instead treats the file as
// a log, where a replacement is a rotation and what was read stays read.
func (s *Store) Mirror(ctx context.Context, path string) {
	newMirrorTailer(path, s.appendLine, s.skip, s.reset).run(ctx)
}

// Generation is how many times a mirroring store has dropped its records.
// Records read under one generation are not a prefix of the next's.
func (s *Store) Generation() uint64 { return s.generation.Load() }

// reset drops every record ahead of a reread. Seq keeps counting, so a Seq is
// never reused for a different record.
func (s *Store) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.records = nil
	s.skipped.Store(0)
	s.generation.Add(1)
	for sub := range s.subs {
		select {
		case sub.reset <- struct{}{}:
		default:
		}
	}
}

// Skipped is how many lines were not records: not a JSON object, or too
// long; in a mirroring store, since the last reset. Their content is never
// logged.
func (s *Store) Skipped() uint64 { return s.skipped.Load() }

func (s *Store) skip(reason string) {
	s.skipped.Add(1)
	slog.Warn("audit: skipped a line in the records file", "reason", reason)
}

// appendLine stores one line from the file. It owns line.
func (s *Store) appendLine(line []byte) {
	var keys struct {
		Unmapped struct {
			RequestID string `json:"cmf.request.request_id"`
		} `json:"unmapped"`
		Agent struct {
			InstanceUID string `json:"instance_uid"`
		} `json:"ai_agent"`
	}
	// A record whose fields have unexpected types still decodes as an
	// object; it is kept, unindexed, because an edited record is exactly
	// what agentop needs to see. Only a line that is not a JSON object is
	// not a record.
	if !json.Valid(line) || len(line) == 0 || line[0] != '{' {
		s.skip("not a JSON object")
		return
	}
	_ = json.Unmarshal(line, &keys)
	s.Append(Record{
		RequestID: keys.Unmapped.RequestID,
		SessionID: keys.Agent.InstanceUID,
		Record:    json.RawMessage(line),
	})
}

// Append stores r, assigning its Seq and ReceivedAt, and hands it to every
// subscriber without blocking.
func (s *Store) Append(r Record) Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return r
	}
	s.next++
	r.Seq = s.next
	r.ReceivedAt = s.now()
	s.records = append(s.records, r)
	if over := len(s.records) - s.max; over > 0 {
		s.records = append(s.records[:0:0], s.records[over:]...)
	}
	for sub := range s.subs {
		select {
		case sub.ch <- r:
		default:
			sub.drops.Add(1)
		}
	}
	return r
}

// List returns records with Seq above after, oldest first, at most limit
// (all when 0 or less), only those naming sessionID when it is set.
func (s *Store) List(sessionID string, after uint64, limit int) []Record {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []Record{}
	for _, r := range s.records {
		if r.Seq <= after || (sessionID != "" && r.SessionID != sessionID) {
			continue
		}
		out = append(out, r)
		if limit > 0 && len(out) == limit {
			break
		}
	}
	return out
}

// Subscribe returns a subscription to records appended from now on, and the
// function that ends it.
func (s *Store) Subscribe() (*Subscription, func()) {
	ch := make(chan Record, subscriberChanBuf)
	reset := make(chan struct{}, 1)
	sub := &Subscription{C: ch, ch: ch, Reset: reset, reset: reset}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		sub.once.Do(func() { close(ch) })
		return sub, func() {}
	}
	s.subs[sub] = struct{}{}
	return sub, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if _, ok := s.subs[sub]; ok {
			delete(s.subs, sub)
			sub.once.Do(func() { close(ch) })
		}
	}
}

// Close ends every subscription. Records appended afterwards are dropped.
func (s *Store) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	for sub := range s.subs {
		sub.once.Do(func() { close(sub.ch) })
		delete(s.subs, sub)
	}
}
