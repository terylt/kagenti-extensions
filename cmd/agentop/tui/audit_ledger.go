package tui

import (
	"context"
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/rossoctl/cortex/cmd/agentop/auditverify"
	"github.com/rossoctl/cortex/cmd/agentop/ledger"
)

// The audit pane's second witness: the ARE ledger that receipts each record. agentop reads it
// directly (--ledger host:port), never through cortex, and holds every record cortex serves
// against the ledger's copy:
//
//   - RECEIPT "✓ #N": the ledger holds this record at chain position N, and its input_hash is the
//     fingerprint agentop recomputed from the bytes cortex served.
//   - "✗ differs": the ledger received a different record under this uid. Cortex's copy was
//     changed after it was receipted, which shows even when the editor recomputed the record's
//     own fingerprint, because they cannot reach the ledger's copy.
//   - "pending": not receipted yet; the adapter ships records as they are written.
//
// A record cortex no longer has can be read back from the ledger by its stream position, so a gap
// row says what the missing record was.

// ledgerTimeout bounds one snapshot, so an unreachable ledger cannot stall the pane.
const ledgerTimeout = 3 * time.Second

type ledgerLoadedMsg struct {
	snap ledger.Snapshot
	err  error
}

type ledgerProofMsg struct {
	uid   string
	proof ledger.Proof
	err   error
}

// ledgerClient dials the ledger on first use. Dialing does not connect, so this never blocks.
func (m *model) ledgerClient() (*ledger.Client, error) {
	if m.audit.ledger != nil {
		return m.audit.ledger, nil
	}
	c, err := ledger.Dial(m.audit.ledgerAddr)
	if err != nil {
		return nil, err
	}
	m.audit.ledger = c
	return c, nil
}

// loadLedgerCmd fetches a snapshot, or nil when no ledger is configured.
func (m *model) loadLedgerCmd() tea.Cmd {
	if m.audit.ledgerAddr == "" {
		return nil
	}
	c, err := m.ledgerClient()
	if err != nil {
		return func() tea.Msg { return ledgerLoadedMsg{err: err} }
	}
	parent := m.ctx
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(parent, ledgerTimeout)
		defer cancel()
		snap, err := c.Snapshot(ctx)
		return ledgerLoadedMsg{snap: snap, err: err}
	}
}

// verifyProofCmd asks the ledger to verify the receipt of the record with uid.
func (m *model) verifyProofCmd(uid string, e ledger.Entry) tea.Cmd {
	c, err := m.ledgerClient()
	if err != nil {
		return nil
	}
	parent := m.ctx
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(parent, ledgerTimeout)
		defer cancel()
		p, err := c.VerifyProof(ctx, e)
		return ledgerProofMsg{uid: uid, proof: p, err: err}
	}
}

func (m *model) applyLedgerSnapshot(msg ledgerLoadedMsg) {
	m.audit.ledgerErr = msg.err
	if msg.err == nil {
		snap := msg.snap
		m.audit.ledgerSnap = &snap
	}
	if m.pane == paneAudit && !m.audit.detail {
		m.rebuildAuditTable()
	}
}

func (m *model) applyLedgerProof(msg ledgerProofMsg) {
	if msg.uid != m.audit.proofUID {
		return
	}
	m.audit.proof, m.audit.proofErr, m.audit.proofDone = msg.proof, msg.err, true
	if m.audit.detail {
		m.renderAuditDetail()
	}
}

// receiptState is what the ledger says about one record.
type receiptState int

const (
	receiptNone    receiptState = iota // no ledger configured
	receiptLoading                     // first snapshot not in yet
	receiptError                       // the ledger could not be read
	receiptPending                     // not receipted yet
	receiptMatches                     // receipted, same fingerprint
	receiptDiffers                     // receipted, different fingerprint
)

func (m *model) receipt(r auditverify.Result) (receiptState, ledger.Entry) {
	switch {
	case m.audit.ledgerAddr == "":
		return receiptNone, ledger.Entry{}
	case m.audit.ledgerSnap == nil && m.audit.ledgerErr != nil:
		return receiptError, ledger.Entry{}
	case m.audit.ledgerSnap == nil:
		return receiptLoading, ledger.Entry{}
	case r.UID == "":
		return receiptNone, ledger.Entry{}
	}
	e, ok := m.audit.ledgerSnap.ByUID[r.UID]
	switch {
	case !ok:
		return receiptPending, e
	case e.InputHash == r.Fingerprint:
		return receiptMatches, e
	}
	return receiptDiffers, e
}

func (m *model) receiptCell(r auditverify.Result) string {
	state, e := m.receipt(r)
	switch state {
	case receiptLoading:
		return "…"
	case receiptError:
		return "? ledger"
	case receiptPending:
		return "pending"
	case receiptMatches:
		return fmt.Sprintf("✓ #%d", e.Position)
	case receiptDiffers:
		return "✗ differs"
	}
	return "—"
}

// ledgerChanges lists what changed in record i since the ledger receipted it: the fields where
// cortex's copy and the ledger's differ. Nil unless the ledger disputes the record.
func (m *model) ledgerChanges(i int) []auditverify.Change {
	if i < 0 || i >= len(m.audit.records) || i >= len(m.audit.report.Results) {
		return nil
	}
	state, e := m.receipt(m.audit.report.Results[i])
	if state != receiptDiffers || len(e.Content) == 0 {
		return nil
	}
	changes, err := auditverify.Changes(e.Content, m.audit.records[i].Record)
	if err != nil {
		return nil
	}
	return changes
}

// ledgerHolds describes what the ledger kept for a run of missing stream positions.
func (m *model) ledgerHolds(epoch uint64, stream string, from, to uint64) string {
	if m.audit.ledgerSnap == nil {
		return "lost or deleted"
	}
	var found int
	var only ledger.Entry
	for seq := from; seq <= to; seq++ {
		if e, ok := m.audit.ledgerSnap.ByStamp[ledger.Stamp{Epoch: epoch, StreamID: stream, StreamSeq: seq}]; ok {
			found++
			only = e
		}
	}
	switch {
	case found == 0:
		return "not in the ledger either"
	case found == 1 && from == to:
		return "ledger: " + only.Action
	}
	return fmt.Sprintf("ledger kept %d of %d", found, to-from+1)
}

// ledgerTitle is the title's note on the ledger, or "" without one.
func (m *model) ledgerTitle() string {
	switch {
	case m.audit.ledgerAddr == "":
		return ""
	case m.audit.ledgerSnap == nil && m.audit.ledgerErr != nil:
		return "ledger unreachable"
	case m.audit.ledgerSnap == nil:
		return "ledger …"
	}
	for _, typ := range ledger.EntryTypes {
		if c, ok := m.audit.ledgerSnap.Chains[typ]; ok && !c.Valid {
			return "LEDGER CHAIN BROKEN"
		}
	}
	return fmt.Sprintf("ledger ✓ %d receipts", len(m.audit.ledgerSnap.ByUID))
}

// receiptDetail is the detail view's receipt lines.
// line writes a label and value; alarm writes one in the error colour, for what the reader
// opened the record to see.
func (m *model) receiptDetail(r auditverify.Result, line, alarm func(k, v string)) {
	state, e := m.receipt(r)
	switch state {
	case receiptNone:
		cmd := "agentop observe"
		if m.auditFile != nil {
			cmd = "agentop audit"
		}
		line("receipt", "— (no ledger: run "+cmd+" --ledger host:port)")
		return
	case receiptLoading:
		line("receipt", "… reading the ledger")
		return
	case receiptError:
		line("receipt", "? the ledger could not be read: "+m.audit.ledgerErr.Error())
		return
	case receiptPending:
		line("receipt", "pending: the ledger has no entry for this record yet")
		return
	case receiptMatches:
		line("receipt", fmt.Sprintf("✓ chain position %d; the ledger's copy matches this record", e.Position))
	case receiptDiffers:
		line("receipt", "✗ the ledger received a different record under this uid")
		line("  ledger", e.InputHash)
		line("  here", r.Fingerprint)
	}
	if state == receiptDiffers {
		changes := m.ledgerChanges(m.audit.detailRec)
		switch {
		case len(e.Content) == 0:
			line("changed", "? the ledger kept no copy to compare against")
		case len(changes) == 0:
			line("changed", "? the copies differ, but in no field this view can name")
		default:
			alarm("changed", "since the ledger receipted it:")
			for _, c := range changes {
				alarm("  "+c.Path, shorten(orAbsent(c.Was), 40)+"  →  "+shorten(orAbsent(c.Now), 40))
			}
		}
	}
	line("entry", e.ID)
	line("hash", e.Hash)
	line("previous", e.Previous)
	if !e.Written.IsZero() {
		line("written", e.Written.Local().Format(time.DateTime))
	}
	switch {
	case !m.audit.proofDone:
		line("proof", "… asking the ledger to verify the receipt")
	case m.audit.proofErr != nil:
		line("proof", "? "+m.audit.proofErr.Error())
	case m.audit.proof.Valid:
		line("proof", fmt.Sprintf("✓ the ledger verifies the entry hash and its chain link (position %d)", m.audit.proof.Position))
	default:
		line("proof", "✗ "+m.audit.proof.Reason)
	}
}

func orAbsent(v string) string {
	if v == "" {
		return "(absent)"
	}
	return v
}

func shorten(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}
