package ledger

import (
	"context"
	"net"
	"strconv"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/rossoctl/cortex/cmd/agentop/ledger/ledgerpb"
)

// fakeLedger serves entries in pages of two, so a snapshot has to follow page tokens.
type fakeLedger struct {
	ledgerpb.UnimplementedImmutableLedgerServiceServer
	entries map[string][]*ledgerpb.LedgerEntry
	chainOK bool
}

func (f *fakeLedger) QueryEntries(_ context.Context, r *ledgerpb.QueryEntriesRequest) (*ledgerpb.QueryEntriesResponse, error) {
	all := f.entries[r.GetEntryType()]
	start, _ := strconv.Atoi(r.GetPageToken())
	end := min(start+2, len(all))
	resp := &ledgerpb.QueryEntriesResponse{Entries: all[start:end], TotalCount: int64(len(all))}
	if end < len(all) {
		resp.NextPageToken = strconv.Itoa(end)
	}
	return resp, nil
}

func (f *fakeLedger) VerifyChain(_ context.Context, r *ledgerpb.VerifyChainRequest) (*ledgerpb.VerifyChainResponse, error) {
	n := int64(len(f.entries[r.GetEntryType()]))
	if !f.chainOK {
		return &ledgerpb.VerifyChainResponse{ChainValid: false, EntriesChecked: n, FailureReason: "hash mismatch"}, nil
	}
	return &ledgerpb.VerifyChainResponse{ChainValid: true, EntriesChecked: n}, nil
}

func (f *fakeLedger) VerifyProof(_ context.Context, r *ledgerpb.VerifyProofRequest) (*ledgerpb.VerifyProofResponse, error) {
	for _, e := range f.entries[r.GetEntryType()] {
		if e.GetEntryHash() == r.GetEntryHash() {
			return &ledgerpb.VerifyProofResponse{Valid: true, ChainPosition: e.GetChainPosition()}, nil
		}
	}
	return &ledgerpb.VerifyProofResponse{Valid: false, FailureReason: "no such entry"}, nil
}

func serve(t *testing.T, f *fakeLedger) *Client {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	ledgerpb.RegisterImmutableLedgerServiceServer(srv, f)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	c := &Client{conn: conn, api: ledgerpb.NewImmutableLedgerServiceClient(conn)}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func entry(uid string, seq, pos int64, action string) *ledgerpb.LedgerEntry {
	content := `{"action":"` + action + `","unmapped":{"aid.stream":{"epoch":1792342541877693123,` +
		`"stream_id":"gw-1:decision","stream_seq":` + strconv.FormatInt(seq, 10) + `}}}`
	return &ledgerpb.LedgerEntry{
		EntryId: "e-" + uid, EntryType: "cpex.decision", IdempotencyKey: uid,
		InputHash: "fp-" + uid, EntryHash: "h-" + uid, ChainPosition: pos,
		WrittenTs: 1792342541877, Content: []byte(content),
	}
}

func TestSnapshotFollowsPagesAndIndexesEntries(t *testing.T) {
	f := &fakeLedger{chainOK: true, entries: map[string][]*ledgerpb.LedgerEntry{
		"cpex.decision": {entry("u0", 0, 1, "Allowed"), entry("u1", 1, 2, "Denied"), entry("u2", 2, 3, "Allowed")},
	}}
	snap, err := serve(t, f).Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.ByUID) != 3 || snap.ByUID["u1"].InputHash != "fp-u1" || snap.ByUID["u1"].Position != 2 {
		t.Fatalf("by uid = %+v", snap.ByUID)
	}
	if got := snap.ByUID["u1"].Written.UnixMilli(); got != 1792342541877 {
		t.Errorf("written = %d ms", got)
	}
	// The epoch keeps all 19 digits, so a stored record is found by its exact stamp.
	at := Stamp{Epoch: 1792342541877693123, StreamID: "gw-1:decision", StreamSeq: 1}
	if e, ok := snap.ByStamp[at]; !ok || e.UID != "u1" || e.Action != "Denied" {
		t.Fatalf("by stamp %v = %+v, %v", at, e, ok)
	}
	if c := snap.Chains["cpex.decision"]; !c.Valid || c.Checked != 3 {
		t.Errorf("chain = %+v", c)
	}
}

func TestSnapshotReportsABrokenLedgerChain(t *testing.T) {
	f := &fakeLedger{chainOK: false, entries: map[string][]*ledgerpb.LedgerEntry{"cpex.decision": {entry("u0", 0, 1, "Allowed")}}}
	snap, err := serve(t, f).Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if c := snap.Chains["cpex.decision"]; c.Valid || c.Reason != "hash mismatch" {
		t.Errorf("chain = %+v", c)
	}
}

func TestVerifyProof(t *testing.T) {
	e := entry("u0", 0, 7, "Allowed")
	c := serve(t, &fakeLedger{chainOK: true, entries: map[string][]*ledgerpb.LedgerEntry{"cpex.decision": {e}}})
	p, err := c.VerifyProof(context.Background(), fromProto(e))
	if err != nil || !p.Valid || p.Position != 7 {
		t.Fatalf("proof = %+v, %v", p, err)
	}
	p, err = c.VerifyProof(context.Background(), Entry{Hash: "nope", Type: "cpex.decision"})
	if err != nil || p.Valid || p.Reason == "" {
		t.Fatalf("missing proof = %+v, %v", p, err)
	}
}

func TestAnUnreachableLedgerIsAnError(t *testing.T) {
	c, err := Dial("127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 500_000_000)
	defer cancel()
	if _, err := c.Snapshot(ctx); err == nil {
		t.Fatal("snapshot of an unreachable ledger succeeded")
	}
}
