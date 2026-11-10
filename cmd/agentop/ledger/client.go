// Package ledger reads the ARE immutable ledger that receipts the policy engine's audit records,
// so agentop can hold each record against an independent copy.
//
// The ledger's CPEX adapter writes one entry per record: entry type cpex.decision or
// cpex.effect, idempotency key the record's metadata.uid, input_hash the SHA-256 of the record's
// AID-EMIT-1 covered bytes, which is the record's fingerprint, and content those covered bytes
// themselves. So a record cortex serves matches its receipt when the fingerprint agentop
// recomputes from it equals the entry's input_hash, and a record cortex no longer has can still be
// read back from the ledger.
//
// The ledger is a second witness that does not trust the gateway, which is the point: agentop
// talks to it directly, never through cortex.
package ledger

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/rossoctl/cortex/cmd/agentop/ledger/ledgerpb"
)

// EntryTypes are the entry types the CPEX adapter writes.
var EntryTypes = []string{"cpex.decision", "cpex.effect"}

// queryPageSize is the page size for listing entries.
const queryPageSize = 500

// maxEntries bounds one snapshot, so a long-lived ledger cannot make agentop hold all of it.
const maxEntries = 20000

// Entry is one ledger entry, reduced to what the audit pane uses.
type Entry struct {
	ID        string
	Type      string
	UID       string // the record's metadata.uid (the entry's idempotency key)
	InputHash string // the record's fingerprint, as the ledger received it
	Hash      string // the entry's own hash in the ledger's chain
	Previous  string
	Position  int64
	Written   time.Time
	SignerKey string
	// Content is the record's covered bytes, as the ledger stores them.
	Content []byte
	// Stamp is the record's stream position, read from Content; nil when absent.
	Stamp *Stamp
	// Action is the verdict the stored record claims, read from Content.
	Action string
}

// Stamp is a stream position.
type Stamp struct {
	Epoch     uint64
	StreamID  string
	StreamSeq uint64
}

// ChainCheck is the ledger's own verdict on one entry type's chain.
type ChainCheck struct {
	Valid   bool
	Checked int64
	Reason  string
}

// Snapshot is the ledger's state as one fetch saw it.
type Snapshot struct {
	ByUID map[string]Entry
	// ByStamp finds the entry for a stream position, for a record cortex lacks.
	ByStamp map[Stamp]Entry
	Chains  map[string]ChainCheck
	// Truncated is set when the ledger held more than one snapshot keeps.
	Truncated bool
	FetchedAt time.Time
}

// Proof is the ledger's verification of one receipt.
type Proof struct {
	Valid    bool
	Position int64
	Reason   string
}

// Client is a connection to the ledger's gRPC API.
type Client struct {
	conn *grpc.ClientConn
	api  ledgerpb.ImmutableLedgerServiceClient
}

// Dial connects to the ledger at addr (host:port). The demo ledger listens without TLS on
// localhost; nothing secret crosses this connection, only receipts, and agentop checks what it
// reads rather than trusting the channel.
func Dial(addr string) (*Client, error) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	return &Client{conn: conn, api: ledgerpb.NewImmutableLedgerServiceClient(conn)}, nil
}

// Close ends the connection.
func (c *Client) Close() error { return c.conn.Close() }

// Snapshot lists every entry of the adapter's entry types and asks the ledger to verify each
// type's chain.
func (c *Client) Snapshot(ctx context.Context) (Snapshot, error) {
	snap := Snapshot{
		ByUID:     map[string]Entry{},
		ByStamp:   map[Stamp]Entry{},
		Chains:    map[string]ChainCheck{},
		FetchedAt: time.Now(),
	}
	for _, typ := range EntryTypes {
		token := ""
		for {
			resp, err := c.api.QueryEntries(ctx, &ledgerpb.QueryEntriesRequest{
				EntryType: typ, PageSize: queryPageSize, PageToken: token,
			})
			if err != nil {
				return snap, fmt.Errorf("query %s: %w", typ, err)
			}
			for _, e := range resp.GetEntries() {
				if len(snap.ByUID) >= maxEntries {
					snap.Truncated = true
					break
				}
				entry := fromProto(e)
				if entry.UID != "" {
					snap.ByUID[entry.UID] = entry
				}
				if entry.Stamp != nil {
					snap.ByStamp[*entry.Stamp] = entry
				}
			}
			token = resp.GetNextPageToken()
			if token == "" || snap.Truncated {
				break
			}
		}
		chain, err := c.api.VerifyChain(ctx, &ledgerpb.VerifyChainRequest{EntryType: typ})
		if err != nil {
			return snap, fmt.Errorf("verify chain %s: %w", typ, err)
		}
		snap.Chains[typ] = ChainCheck{
			Valid: chain.GetChainValid(), Checked: chain.GetEntriesChecked(), Reason: chain.GetFailureReason(),
		}
	}
	return snap, nil
}

// VerifyProof asks the ledger to verify one receipt: the entry's hash and its link in the chain.
func (c *Client) VerifyProof(ctx context.Context, e Entry) (Proof, error) {
	resp, err := c.api.VerifyProof(ctx, &ledgerpb.VerifyProofRequest{EntryHash: e.Hash, EntryType: e.Type})
	if err != nil {
		return Proof{}, err
	}
	return Proof{Valid: resp.GetValid(), Position: resp.GetChainPosition(), Reason: resp.GetFailureReason()}, nil
}

func fromProto(e *ledgerpb.LedgerEntry) Entry {
	out := Entry{
		ID:        e.GetEntryId(),
		Type:      e.GetEntryType(),
		UID:       e.GetIdempotencyKey(),
		InputHash: e.GetInputHash(),
		Hash:      e.GetEntryHash(),
		Previous:  e.GetPreviousHash(),
		Position:  e.GetChainPosition(),
		SignerKey: e.GetSignerKeyReference(),
		Content:   e.GetContent(),
	}
	if ts := e.GetWrittenTs(); ts > 0 {
		// Milliseconds since the epoch (timestamp_millis in the ledger's gRPC layer).
		out.Written = time.UnixMilli(ts)
	}
	out.Stamp, out.Action = readContent(out.Content)
	return out
}

// readContent takes the stream stamp and the claimed verdict from a stored record, keeping the
// epoch's digits exact.
func readContent(content []byte) (*Stamp, string) {
	var doc struct {
		Action   string `json:"action"`
		Unmapped struct {
			Stream struct {
				Epoch     json.Number `json:"epoch"`
				StreamID  string      `json:"stream_id"`
				StreamSeq json.Number `json:"stream_seq"`
			} `json:"aid.stream"`
		} `json:"unmapped"`
	}
	if json.Unmarshal(content, &doc) != nil {
		return nil, ""
	}
	s := doc.Unmapped.Stream
	epoch, err1 := strconv.ParseUint(string(s.Epoch), 10, 64)
	seq, err2 := strconv.ParseUint(string(s.StreamSeq), 10, 64)
	if err1 != nil || err2 != nil || s.StreamID == "" {
		return nil, doc.Action
	}
	return &Stamp{Epoch: epoch, StreamID: s.StreamID, StreamSeq: seq}, doc.Action
}
