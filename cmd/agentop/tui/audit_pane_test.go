package tui

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/rossoctl/cortex/cmd/agentop/apiclient"
	"github.com/rossoctl/cortex/cmd/agentop/auditverify"
	"github.com/rossoctl/cortex/cmd/agentop/ledger"
)

// auditFixture is the three signed records (allow, deny, allow) the verifier's tests use, as
// the session API serves them, all naming session claude-1. HOME points at a directory holding
// their public key where agentop looks for it.
func auditFixture(t *testing.T) []apiclient.AuditRecord {
	t.Helper()
	raw, err := os.ReadFile("../auditverify/testdata/records.ndjson")
	if err != nil {
		t.Fatal(err)
	}
	var out []apiclient.AuditRecord
	for i, line := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
		out = append(out, apiclient.AuditRecord{Seq: uint64(i + 1), SessionID: "claude-1", Record: line})
	}
	home := t.TempDir()
	keys := filepath.Join(home, ".cortex", "audit", "keys")
	if err := os.MkdirAll(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	pub, err := os.ReadFile("../auditverify/testdata/signing-public-key.txt")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keys, "cortex-spike-1.pub.pem"), pub, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	return out
}

// auditModel is a model on the audit pane holding records, as after a fetch.
func auditModel(t *testing.T, records []apiclient.AuditRecord) *model {
	t.Helper()
	m := newPickerModel(context.Background(), nil, nil)
	m.width, m.height = 160, 40
	m.pane = paneAudit
	m.audit.keys, m.audit.keyNote = loadAuditKeys(auditKeysDir())
	m.applyAuditPage(auditLoadedMsg{page: &apiclient.AuditPage{Records: records}})
	return m
}

func cells(m *model, col int) []string {
	var out []string
	for _, r := range m.auditTbl.Rows() {
		out = append(out, r[col])
	}
	return out
}

const (
	colTool      = 2
	colVerdict   = 4
	colIntegrity = 5
	colChain     = 6
)

func TestAuditPane_UntouchedRecordsAreSignedAndLinked(t *testing.T) {
	m := auditModel(t, auditFixture(t))
	if got := strings.Join(cells(m, colIntegrity), "|"); got != "✓ signed|✓ signed|✓ signed" {
		t.Errorf("integrity = %s", got)
	}
	if got := strings.Join(cells(m, colChain), "|"); got != "● start|✓ linked|✓ linked" {
		t.Errorf("chain = %s", got)
	}
	if got := strings.Join(cells(m, colVerdict), "|"); got != "Allowed|Denied|Allowed" {
		t.Errorf("verdicts = %s", got)
	}
	for row := range m.auditTbl.Rows() {
		if _, styled := m.auditRowStyle(row); styled {
			t.Errorf("row %d is styled as a problem", row)
		}
	}
	if s := m.auditSummary(); s != "3 records" {
		t.Errorf("summary = %q", s)
	}
}

// The scene the demo turns on: flip the deny to an allow and the pane says so in red, on the
// edited record and on the one after it, whose link no longer matches.
func TestAuditPane_AFlippedVerdictShowsRed(t *testing.T) {
	records := auditFixture(t)
	records[1].Record = bytes.Replace(records[1].Record, []byte(`"action":"Denied"`), []byte(`"action":"Allowed"`), 1)
	m := auditModel(t, records)

	if got := cells(m, colIntegrity)[1]; got != "✗ tampered" {
		t.Errorf("edited record integrity = %s", got)
	}
	if got := cells(m, colVerdict)[1]; got != "Allowed" {
		t.Errorf("edited record verdict = %s, want what it now claims", got)
	}
	if got := cells(m, colChain)[2]; got != "✗ broken" {
		t.Errorf("next record chain = %s", got)
	}
	for row, want := range []bool{false, true, true} {
		st, styled := m.auditRowStyle(row)
		if styled != want || (want && st.GetForeground() != styleError.GetForeground()) {
			t.Errorf("row %d styled = %v, want %v in the error colour", row, styled, want)
		}
	}
	if s := m.auditSummary(); s != "3 records · 2 TAMPERED" {
		t.Errorf("summary = %q", s)
	}
}

func TestAuditPane_ADeletedRecordIsAGapRow(t *testing.T) {
	records := auditFixture(t)
	m := auditModel(t, []apiclient.AuditRecord{records[0], records[2]})
	tools := cells(m, colTool)
	if len(tools) != 3 || tools[1] != "⚠ 1 MISSING" || m.auditTbl.Rows()[1][3] != "seq 1" {
		t.Fatalf("rows = %q", tools)
	}
	if _, styled := m.auditRowStyle(1); !styled {
		t.Error("the gap row is not styled")
	}
	if got := cells(m, colChain)[2]; got != "⚠ gap" {
		t.Errorf("record after the gap: chain = %s", got)
	}
}

// Scoped to one session the stream's other records are absent by choice, so no gap is drawn.
func TestAuditPane_ScopedToASessionDrawsNoGapRows(t *testing.T) {
	records := auditFixture(t)
	records[1].SessionID = "someone-else"
	m := auditModel(t, records)
	m.audit.session = "claude-1"
	m.rebuildAuditTable()
	if tools := cells(m, colTool); len(tools) != 2 || strings.Contains(strings.Join(tools, ""), "missing") {
		t.Fatalf("rows = %q", tools)
	}
}

func TestAuditPane_WithoutKeysSignaturesAreUncheckedNotFailed(t *testing.T) {
	records := auditFixture(t)
	t.Setenv("HOME", t.TempDir())
	m := auditModel(t, records)
	if got := strings.Join(cells(m, colIntegrity), "|"); got != "? no key|? no key|? no key" {
		t.Errorf("integrity = %s", got)
	}
}

func key(r rune) tea.KeyMsg { return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}} }

// V opens the pane scoped to the session on screen, Enter opens a record, and esc backs out one
// level at a time.
func TestAuditPane_KeysOpenScopeAndBackOut(t *testing.T) {
	records := auditFixture(t)
	m := newPickerModel(context.Background(), nil, nil)
	m.width, m.height = 160, 40
	m.client = apiclient.New("http://127.0.0.1:1")
	m.pane = paneEvents
	m.selectedSess = "claude-1"
	m.layout()

	if cmd := m.handleKey(key('V')); cmd == nil || m.pane != paneAudit {
		t.Fatalf("V: pane = %v, cmd = %v", m.pane, cmd)
	}
	if m.audit.session != "claude-1" {
		t.Errorf("scope = %q, want the session on screen", m.audit.session)
	}
	m.applyAuditPage(auditLoadedMsg{page: &apiclient.AuditPage{Records: records}})

	m.handleKey(key('s'))
	if m.audit.session != "" {
		t.Errorf("s: scope = %q, want all sessions", m.audit.session)
	}
	m.handleKey(tea.KeyMsg{Type: tea.KeyEnter})
	if !m.audit.detail || !strings.Contains(m.audit.vp.View(), "✓ signed") {
		t.Fatalf("enter: detail = %v\n%s", m.audit.detail, m.audit.vp.View())
	}
	m.handleKey(tea.KeyMsg{Type: tea.KeyEsc})
	if m.audit.detail || m.pane != paneAudit {
		t.Fatalf("first esc: detail = %v, pane = %v", m.audit.detail, m.pane)
	}
	m.handleKey(tea.KeyMsg{Type: tea.KeyEsc})
	if m.pane != paneEvents {
		t.Fatalf("second esc: pane = %v, want events", m.pane)
	}
}

// A streamed record joins the set once the stored ones are loaded, and is verified with them.
func TestAuditPane_StreamedRecordsAreVerifiedWithTheRest(t *testing.T) {
	records := auditFixture(t)
	m := newPickerModel(context.Background(), nil, nil)
	m.pane = paneAudit
	m.audit.keys, _ = loadAuditKeys(auditKeysDir())

	m.handleStreamEvent(apiclient.StreamEvent{Audit: &records[2]})
	if len(m.audit.records) != 0 {
		t.Fatal("a record streamed before the first load was kept")
	}
	m.applyAuditPage(auditLoadedMsg{page: &apiclient.AuditPage{Records: records[:2]}})
	m.handleStreamEvent(apiclient.StreamEvent{Audit: &records[2]})
	m.handleStreamEvent(apiclient.StreamEvent{Audit: &records[2]}) // a duplicate is ignored
	if got := strings.Join(cells(m, colChain), "|"); got != "● start|✓ linked|✓ linked" {
		t.Errorf("chain after streaming = %s", got)
	}
}

// A record from a later epoch starts a new stream: a marker row, and no gap for its seq 0.
func TestAuditPane_ANewEpochIsMarkedNotAGap(t *testing.T) {
	records := auditFixture(t)
	later := records[0]
	later.Seq = 4
	later.Record = bytes.Replace(later.Record, []byte(`"epoch":1792342541877693000`), []byte(`"epoch":1792342541877693001`), 1)
	m := auditModel(t, append(records, later))
	tools := cells(m, colTool)
	if len(tools) != 5 || tools[3] != "── NEW EPOCH ──" {
		t.Fatalf("rows = %q", tools)
	}
	if strings.Contains(strings.Join(tools, ""), "MISSING") {
		t.Errorf("a new epoch was drawn as a gap: %q", tools)
	}
}

// receiptsFor is a ledger snapshot holding a receipt for each record m has, as the adapter
// would have written it: input_hash the record's fingerprint, content readable by stamp.
func receiptsFor(m *model, action func(i int) string) *ledger.Snapshot {
	snap := &ledger.Snapshot{ByUID: map[string]ledger.Entry{}, ByStamp: map[ledger.Stamp]ledger.Entry{},
		Chains: map[string]ledger.ChainCheck{"cpex.decision": {Valid: true}}}
	for i, r := range m.audit.report.Results {
		e := ledger.Entry{ID: fmt.Sprint("e", i), Type: "cpex.decision", UID: r.UID, InputHash: r.Fingerprint,
			Position: int64(10 + i), Action: action(i)}
		snap.ByUID[r.UID] = e
		snap.ByStamp[ledger.Stamp{Epoch: r.Stamp.Epoch, StreamID: r.Stamp.StreamID, StreamSeq: r.Stamp.StreamSeq}] = e
	}
	return snap
}

func withLedger(m *model, snap *ledger.Snapshot) {
	m.audit.ledgerAddr = "ledger.test:1"
	m.applyLedgerSnapshot(ledgerLoadedMsg{snap: *snap})
}

const colReceipt = 7

func TestAuditPane_ReceiptsMatchTheLedger(t *testing.T) {
	m := auditModel(t, auditFixture(t))
	withLedger(m, receiptsFor(m, func(int) string { return "Allowed" }))
	if got := strings.Join(cells(m, colReceipt), "|"); got != "✓ #10|✓ #11|✓ #12" {
		t.Errorf("receipts = %s", got)
	}
	if s := m.auditSummary(); s != "3 records · ledger ✓ 3 receipts" {
		t.Errorf("summary = %q", s)
	}
}

// What only the ledger can show: a record that passes every local check, but is not what the
// ledger receipted under its uid. Cortex's copy was replaced after shipping.
func TestAuditPane_TheLedgerCatchesWhatLocalChecksCannot(t *testing.T) {
	m := auditModel(t, auditFixture(t))
	snap := receiptsFor(m, func(int) string { return "Allowed" })
	uid := m.audit.report.Results[1].UID
	e := snap.ByUID[uid]
	e.InputHash = strings.Repeat("0", 64)
	snap.ByUID[uid] = e
	withLedger(m, snap)

	if got := cells(m, colIntegrity)[1]; got != "✓ signed" {
		t.Fatalf("setup: the record should pass locally, integrity = %s", got)
	}
	if got := cells(m, colReceipt)[1]; got != "✗ differs" {
		t.Errorf("receipt = %s", got)
	}
	if st, styled := m.auditRowStyle(1); !styled || st.GetForeground() != styleError.GetForeground() {
		t.Error("a record the ledger disagrees with is not drawn in the error colour")
	}
	if s := m.auditSummary(); !strings.Contains(s, "1 DIFFERS FROM THE LEDGER") {
		t.Errorf("summary = %q", s)
	}
}

// Deleted from cortex's file, but the ledger kept it, and says what it was.
func TestAuditPane_AGapSaysWhatTheLedgerKept(t *testing.T) {
	records := auditFixture(t)
	full := auditModel(t, records)
	snap := receiptsFor(full, func(i int) string { return []string{"Allowed", "Denied", "Allowed"}[i] })

	m := auditModel(t, []apiclient.AuditRecord{records[0], records[2]})
	withLedger(m, snap)
	if got := m.auditTbl.Rows()[1][colVerdict]; got != "ledger: Denied" {
		t.Errorf("gap row verdict = %q", got)
	}
}

func TestAuditPane_ReceiptStatesWithoutAMatch(t *testing.T) {
	m := auditModel(t, auditFixture(t))
	if got := cells(m, colReceipt)[0]; got != "—" {
		t.Errorf("no ledger: receipt = %s", got)
	}
	m.audit.ledgerAddr = "ledger.test:1"
	m.rebuildAuditTable()
	if got := cells(m, colReceipt)[0]; got != "…" {
		t.Errorf("before the first snapshot: receipt = %s", got)
	}
	m.applyLedgerSnapshot(ledgerLoadedMsg{err: fmt.Errorf("connection refused")})
	if got := cells(m, colReceipt)[0]; got != "? ledger" || !strings.Contains(m.auditSummary(), "ledger unreachable") {
		t.Errorf("unreachable: receipt = %s, summary = %q", got, m.auditSummary())
	}
	withLedger(m, &ledger.Snapshot{ByUID: map[string]ledger.Entry{}, ByStamp: map[ledger.Stamp]ledger.Entry{},
		Chains: map[string]ledger.ChainCheck{"cpex.decision": {Valid: false}}})
	if got := cells(m, colReceipt)[0]; got != "pending" || !strings.Contains(m.auditSummary(), "LEDGER CHAIN BROKEN") {
		t.Errorf("empty ledger: receipt = %s, summary = %q", got, m.auditSummary())
	}
}

// The detail view asks the ledger to verify the receipt and shows its answer.
func TestAuditPane_DetailShowsTheReceiptProof(t *testing.T) {
	m := auditModel(t, auditFixture(t))
	m.layout()
	withLedger(m, receiptsFor(m, func(int) string { return "Allowed" }))
	if cmd := m.showAuditDetail(); cmd == nil {
		t.Fatal("no proof was requested for a receipted record")
	}
	if !strings.Contains(m.audit.vp.View(), "asking the ledger") {
		t.Errorf("before the proof:\n%s", m.audit.vp.View())
	}
	m.applyLedgerProof(ledgerProofMsg{uid: m.audit.proofUID, proof: ledger.Proof{Valid: true, Position: 10}})
	view := m.audit.vp.View()
	if !strings.Contains(view, "chain position 10") || !strings.Contains(view, "the ledger verifies") {
		t.Errorf("after the proof:\n%s", view)
	}
}

// A reconnect can be a restarted cortex, whose store re-read the file: the pane refetches.
func TestAuditPane_ARefetchFollowsAReconnect(t *testing.T) {
	m := newPickerModel(context.Background(), nil, nil)
	m.client = apiclient.New("http://127.0.0.1:1")
	m.pane = paneSessions
	open := streamMsg(apiclient.StreamEvent{Status: apiclient.StreamStatus{Phase: "open"}})
	if _, cmd := m.Update(open); cmd == nil {
		t.Fatal("setup: the stream should be re-pumped")
	}
	m.audit.loaded = true
	_, cmd := m.Update(open)
	if cmd == nil {
		t.Fatal("no command after a reconnect")
	}
	if _, isBatch := cmd().(tea.BatchMsg); !isBatch {
		t.Error("a reconnect with audit records loaded did not also refetch them")
	}
}

// The identity and response records of a call name no tool; the pane takes it from the
// authorize record with the same request id.
func TestAuditPane_SiblingRecordsBorrowTheToolName(t *testing.T) {
	records := auditFixture(t)
	for i := range records {
		records[i].RequestID = "7-bef70a"
	}
	records[0].Record = bytes.Replace(records[0].Record, []byte(`"tool":{"name":"get_compensation"`), []byte(`"tool":{"name":""`), 1)
	m := auditModel(t, records)
	if got := cells(m, colTool)[0]; got != "get_compensation" {
		t.Errorf("tool = %q, want it borrowed from the call's other records", got)
	}
}

// The identity filter hides only identity checks that passed everything: a flagged record is
// evidence and always shows.
func TestAuditPane_TheIdentityFilterNeverHidesAFlaggedRecord(t *testing.T) {
	m := newPickerModel(context.Background(), nil, nil)
	identity := apiclient.AuditRecord{Record: []byte(`{"unmapped":{"aid.decision":{"steps":[{"plugin":"jwt-user"}]}}}`)}
	authorize := apiclient.AuditRecord{Record: []byte(`{"unmapped":{"aid.decision":{"steps":[{"plugin":"apl::tool::x::pre"}]}}}`)}
	clean := auditverify.Result{FingerprintOK: true, Signature: auditverify.SignatureValid, Link: auditverify.LinkIntact}

	if !m.auditHidden(identity, clean) {
		t.Error("a clean identity check is not hidden")
	}
	if m.auditHidden(authorize, clean) {
		t.Error("a decision was hidden")
	}
	for name, r := range map[string]auditverify.Result{
		"tampered":    {FingerprintOK: false, Signature: auditverify.SignatureInvalid, Link: auditverify.LinkIntact},
		"broken":      {FingerprintOK: true, Signature: auditverify.SignatureValid, Link: auditverify.LinkBroken},
		"after a gap": {FingerprintOK: true, Signature: auditverify.SignatureValid, Link: auditverify.LinkMissing},
	} {
		if m.auditHidden(identity, r) {
			t.Errorf("a %s identity record was hidden", name)
		}
	}
}

func TestAuditPane_AModifiedAllowSaysSo(t *testing.T) {
	if got := (auditFields{Action: "Modified"}).verdict(); got != "Allowed (modified)" {
		t.Errorf("verdict = %q", got)
	}
}

// A hidden identity check that opens a new epoch still gets its marker, and hiding one draws no
// gap. Unsealed records, so the identity checks pass and the filter really hides them.
func TestAuditPane_TheIdentityFilterKeepsTheEpochMarker(t *testing.T) {
	rec := func(seq uint64, epoch int, step string) apiclient.AuditRecord {
		return apiclient.AuditRecord{Seq: seq, Record: []byte(fmt.Sprintf(
			`{"action":"Allowed","tool":{"name":"t"},"unmapped":{"aid.stream":{"epoch":%d,"stream_id":"s","stream_seq":%d},`+
				`"aid.decision":{"steps":[{"plugin":%q}]}}}`, epoch, (seq-1)%2, step))}
	}
	m := auditModel(t, []apiclient.AuditRecord{
		rec(1, 1, "jwt-user"), rec(2, 1, "apl::tool::t::pre"),
		rec(3, 2, "jwt-user"), rec(4, 2, "apl::tool::t::pre"),
	})
	m.audit.hideIdentity = true
	m.rebuildAuditTable()
	phases := cells(m, 3)
	if got := strings.Join(phases, "|"); got != "authorize|restarted|authorize" {
		t.Fatalf("phases = %q, want the two decisions with the epoch marker between", got)
	}
	if !strings.HasPrefix(m.auditSummary(), "2 decisions") {
		t.Errorf("summary = %q", m.auditSummary())
	}
}

// With the ledger's copy of the record, the pane names what the insider changed: on the row,
// and field by field in the detail view.
func TestAuditPane_TheLedgerShowsWhatWasChanged(t *testing.T) {
	original := auditFixture(t)
	clean := auditModel(t, original)
	snap := receiptsFor(clean, func(int) string { return "Allowed" })
	for i, r := range clean.audit.report.Results {
		e := snap.ByUID[r.UID]
		e.Content = original[i].Record // what the adapter shipped before the edit
		snap.ByUID[r.UID] = e
	}

	tampered := append([]apiclient.AuditRecord{}, original...)
	tampered[1].Record = bytes.Replace(tampered[1].Record, []byte(`"action":"Denied"`), []byte(`"action":"Allowed"`), 1)
	m := auditModel(t, tampered)
	m.layout()
	withLedger(m, snap)

	if got := cells(m, colVerdict)[1]; got != "Allowed (was Denied)" {
		t.Errorf("verdict = %q", got)
	}
	m.handleKey(key('t'))
	if m.auditTbl.Cursor() != 1 {
		t.Fatalf("t moved the cursor to row %d, want the tampered row 1", m.auditTbl.Cursor())
	}
	m.showAuditDetail()
	view := m.audit.vp.View()
	if !strings.Contains(view, "since the ledger receipted it") || !strings.Contains(view, `"Denied"  →  "Allowed"`) {
		t.Errorf("detail:\n%s", view)
	}
}

// A record deleted from the log: m finds the gap, and ↵ reads the record back from the ledger and
// proves it is the one deleted, because the next record links to its fingerprint.
func TestAuditPane_AGapShowsTheDeletedRecordFromTheLedger(t *testing.T) {
	original := auditFixture(t)
	full := auditModel(t, original)
	snap := receiptsFor(full, func(i int) string { return []string{"Allowed", "Denied", "Allowed"}[i] })
	for i, r := range full.audit.report.Results {
		e := snap.ByUID[r.UID]
		e.Content = original[i].Record
		snap.ByUID[r.UID] = e
		snap.ByStamp[ledger.Stamp{Epoch: r.Stamp.Epoch, StreamID: r.Stamp.StreamID, StreamSeq: r.Stamp.StreamSeq}] = e
	}

	m := auditModel(t, []apiclient.AuditRecord{original[0], original[2]})
	m.layout()

	// Without the ledger, the gap says only that records existed.
	m.handleKey(key('m'))
	m.showAuditDetail()
	if v := m.audit.vp.View(); !strings.Contains(v, "not connected") {
		t.Errorf("gap without a ledger:\n%s", v)
	}
	m.audit.detail = false

	withLedger(m, snap)
	m.handleKey(key('m'))
	if m.audit.rows[m.auditTbl.Cursor()].kind != auditRowGap {
		t.Fatalf("m left the cursor on row %d, not the gap", m.auditTbl.Cursor())
	}
	if cmd := m.showAuditDetail(); cmd == nil {
		t.Error("no proof was requested for the ledger's copy")
	}
	view := m.audit.vp.View()
	for _, want := range []string{"cortex's log no longer has", "the ledger kept it", "this is the deleted record", "Denied"} {
		if !strings.Contains(view, want) {
			t.Errorf("gap detail lacks %q:\n%s", want, view)
		}
	}
}

// An inference record names a model rather than a tool: the response record in ai_model, the
// request record only in its policy step.
func TestAuditFields_TargetNamesTheToolOrTheModel(t *testing.T) {
	for _, c := range []struct{ name, record, want string }{
		{"tool call", `{"tool":{"name":"send_email"}}`, "send_email"},
		{"response", `{"ai_model":{"name":"gpt-4o-mini"},"unmapped":{"aid.decision":{"steps":[{"plugin":"apl::llm::gpt-4o-mini::post"}]}}}`, "model gpt-4o-mini"},
		{"request", `{"unmapped":{"aid.decision":{"steps":[{"plugin":"apl::llm::o3::pre"}]}}}`, "model o3"},
		{"catch-all route", `{"unmapped":{"aid.decision":{"steps":[{"plugin":"apl::llm::*::pre"}]}}}`, "model (unlisted)"},
		{"identity", `{"unmapped":{"aid.decision":{"steps":[{"plugin":"jwt-user"}]}}}`, ""},
	} {
		if got := parseAuditFields([]byte(c.record)).target(); got != c.want {
			t.Errorf("%s: target = %q, want %q", c.name, got, c.want)
		}
	}
}
