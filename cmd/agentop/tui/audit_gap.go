package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/rossoctl/cortex/cmd/agentop/auditverify"
	"github.com/rossoctl/cortex/cmd/agentop/ledger"
)

// A gap row stands for records that existed and are not in cortex's log: lost, or deleted. The
// ledger received them as they were written, so the gap detail reads them back from it, and
// proves the copy is the missing record rather than one the ledger merely claims: the record
// after the gap names its predecessor's fingerprint, and the last missing record's ledger copy
// has exactly that fingerprint.

// nextGapRow moves the cursor to the next gap row, wrapping around; it stays put without one.
func (m *model) nextGapRow() {
	n := len(m.audit.rows)
	start := m.auditTbl.Cursor()
	for step := 1; step <= n; step++ {
		row := (start + step) % n
		if m.audit.rows[row].kind == auditRowGap {
			m.auditTbl.SetCursor(row)
			return
		}
	}
}

// showGapDetail opens a gap row: what the ledger kept for each missing position.
func (m *model) showGapDetail(gap auditRow) tea.Cmd {
	m.audit.detailGap = &gap
	m.audit.proofUID, m.audit.proof, m.audit.proofErr, m.audit.proofDone = "", ledger.Proof{}, nil, false
	var cmd tea.Cmd
	if e, ok := m.gapEntry(gap, gap.to); ok {
		m.audit.proofUID = e.UID
		cmd = m.verifyProofCmd(e.UID, e)
	}
	m.renderGapDetail()
	m.audit.vp.GotoTop()
	m.audit.detail = true
	return cmd
}

func (m *model) gapEntry(gap auditRow, seq uint64) (ledger.Entry, bool) {
	if m.audit.ledgerSnap == nil {
		return ledger.Entry{}, false
	}
	e, ok := m.audit.ledgerSnap.ByStamp[ledger.Stamp{Epoch: gap.epoch, StreamID: gap.stream, StreamSeq: seq}]
	return e, ok
}

func (m *model) renderGapDetail() {
	gap := m.audit.detailGap
	var b strings.Builder
	format := func(k, v string) string {
		if v == "" {
			v = emptyCell
		}
		return fmt.Sprintf("%-12s %s", k, v)
	}
	line := func(k, v string) { b.WriteString(format(k, v) + "\n") }
	alarm := func(k, v string) { b.WriteString(styleError.Render(format(k, v)) + "\n") }
	good := func(k, v string) { b.WriteString(styleOK.Render(format(k, v)) + "\n") }

	span, which := fmt.Sprintf("seq %d", gap.from), "this record"
	if gap.to > gap.from {
		span, which = fmt.Sprintf("seq %d–%d", gap.from, gap.to), "these records"
	}
	line("missing", fmt.Sprintf("%d record%s: %s  epoch %d  %s", gap.to-gap.from+1, plural(int(gap.to-gap.from+1)), gap.stream, gap.epoch, span))
	alarm("deleted", "cortex's log no longer has "+which)
	if m.audit.ledgerSnap == nil {
		line("ledger", "— not connected: nothing more is known than that they existed")
		m.audit.vp.SetContent(b.String())
		return
	}

	var next []byte
	if gap.rec >= 0 && gap.rec < len(m.audit.records) {
		next = m.audit.records[gap.rec].Record
	}
	for seq := gap.from; seq <= gap.to; seq++ {
		b.WriteString("\n")
		e, ok := m.gapEntry(*gap, seq)
		if !ok {
			alarm(fmt.Sprintf("seq %d", seq), "not in the ledger either: lost before it was receipted")
			continue
		}
		good(fmt.Sprintf("seq %d", seq), fmt.Sprintf("the ledger kept it, at chain position %d", e.Position))
		fp, err := auditverify.Fingerprint(e.Content)
		switch {
		case err != nil:
			alarm("proven", "? the ledger's copy does not parse: "+err.Error())
		case fp != e.InputHash:
			alarm("proven", "✗ the ledger's copy does not match its own receipt")
		case seq == gap.to && next != nil && auditverify.PrevFingerprint(next) == fp:
			good("proven", "✓ its fingerprint is the one the next record links to: this is the deleted record")
		case seq == gap.to && next != nil:
			alarm("proven", "✗ the next record links to a different predecessor")
		default:
			good("proven", "✓ the ledger's copy matches its receipt")
		}
		f := parseAuditFields(e.Content)
		tool := f.target()
		if tool == "" {
			tool = emptyCell
		}
		line("tool", tool)
		line("verdict", f.verdict())
		if f.StatusCode != "" {
			line("rule", f.StatusCode)
		}
		if seq == gap.to && m.audit.proofUID == e.UID {
			switch {
			case !m.audit.proofDone:
				line("receipt", "… asking the ledger to verify the receipt")
			case m.audit.proofErr != nil:
				line("receipt", "? "+m.audit.proofErr.Error())
			case m.audit.proof.Valid:
				good("receipt", fmt.Sprintf("✓ the ledger verifies the entry hash and its chain link (position %d)", m.audit.proof.Position))
			default:
				alarm("receipt", "✗ "+m.audit.proof.Reason)
			}
		}
		b.WriteString("\n")
		b.WriteString(ColorizeJSONBytes(e.Content))
		b.WriteString("\n")
	}
	m.audit.vp.SetContent(b.String())
}
