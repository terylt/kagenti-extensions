package tui

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/rossoctl/cortex/cmd/agentop/apiclient"
	"github.com/rossoctl/cortex/cmd/agentop/auditverify"
	"github.com/rossoctl/cortex/cmd/agentop/ledger"
	"github.com/rossoctl/cortex/cmd/agentop/tui/table"
)

// The audit pane lists the signed OCSF records the policy engine's ocsf-audit sink writes, and
// checks every one of them here, in agentop, from the record bytes and the signing authority's
// public key. Cortex serves the records and never says whether they verify: a proxy vouching for
// its own audit trail would prove nothing.
//
// What a row shows:
//
//   - INTEGRITY: the record's content against its fingerprint and signature. "✗ tampered" means
//     the bytes changed after they were hashed.
//   - CHAIN: the link to the record before it. "✗ broken" means that record was changed; "⚠ gap"
//     means it is missing.
//   - RECEIPT: the independent ledger's receipt, when agentop is given one; see audit_ledger.go.
//
// Between records the pane inserts a row for every missing stream position (records that existed
// and did not arrive, or were deleted) and one where a new epoch starts (the engine restarted, so
// the stream starts over at 0 and that is not loss).

// auditFetchLimit is how many records one open fetches, the server's maximum page.
const auditFetchLimit = 5000

// auditKeysDir is where agentop looks for the authority's public keys: one PEM file per key,
// named <key id>.pub.pem, so a record's signature_key_id picks its key.
func auditKeysDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".cortex", "audit", "keys")
}

// auditState is everything the audit pane holds.
type auditState struct {
	records []apiclient.AuditRecord
	report  auditverify.Report
	loaded  bool
	err     error
	keys    auditverify.Keys
	keyNote string
	// keysDir overrides auditKeysDir; `agentop audit --keys` sets it.
	keysDir string
	// session scopes the rows to one cortex session; "" shows every record. scopeTo is the
	// session the pane was opened from, which `s` toggles to and from.
	session string
	scopeTo string
	// rows maps each table row to what it draws, in the table's order.
	rows []auditRow
	// detailGap is the gap row open in the detail view; nil when a record is open.
	detailGap *auditRow
	// hideIdentity leaves out the identity-check records each call produces, which carry no
	// decision of their own; see auditHidden.
	hideIdentity bool
	detail       bool
	detailRec    int
	vp           viewport.Model

	// The ledger, when --ledger names one. See audit_ledger.go.
	ledgerAddr string
	ledger     *ledger.Client
	ledgerSnap *ledger.Snapshot
	ledgerErr  error
	// The receipt proof for the record open in the detail view.
	proofUID  string
	proof     ledger.Proof
	proofErr  error
	proofDone bool
}

type auditRowKind int

const (
	auditRowRecord auditRowKind = iota
	auditRowGap
	auditRowEpoch
)

type auditRow struct {
	kind auditRowKind
	// rec indexes records and report.Results: the record a record row shows, or for a gap row
	// the record right after the gap, whose link names the last missing record.
	rec int
	// For a gap row, the stream and the missing positions, inclusive.
	epoch    uint64
	stream   string
	from, to uint64
}

func auditColumns() []table.Column {
	return []table.Column{
		{Title: "SEQ", Width: 5},
		{Title: "TIME", Width: 8},
		{Title: "TOOL", Width: 20},
		{Title: "PHASE", Width: 14},
		{Title: "VERDICT", Width: 20},
		{Title: "INTEGRITY", Width: 12},
		{Title: "CHAIN", Width: 10},
		{Title: "RECEIPT", Width: 10},
		{Title: "SESSION", Width: 16},
	}
}

func newAuditTable() table.Model {
	t := table.New(table.WithColumns(auditColumns()), table.WithFocused(true))
	t.SetStyles(tableStyles())
	return t
}

type auditLoadedMsg struct {
	page *apiclient.AuditPage
	err  error
	// fileGen is the store generation an audit-file page was read under.
	fileGen uint64
}

func (m *model) loadAuditCmd() tea.Cmd {
	if src := m.auditFile; src != nil {
		return func() tea.Msg {
			page, gen := src.page()
			return auditLoadedMsg{page: page, fileGen: gen}
		}
	}
	client, ctx := m.client, m.ctx
	return func() tea.Msg {
		page, err := client.GetAudit(ctx, "", 0, auditFetchLimit)
		return auditLoadedMsg{page: page, err: err}
	}
}

// auditKeysDir is where this viewer reads public keys: the directory `agentop audit --keys`
// named, or the default.
func (m *model) auditKeysDir() string {
	if m.audit.keysDir != "" {
		return m.audit.keysDir
	}
	return auditKeysDir()
}

// loadAuditKeys reads every <key id>.pub.pem under dir. A missing directory is not an error:
// signatures then show "? no key", and fingerprints and links are still checked.
func loadAuditKeys(dir string) (auditverify.Keys, string) {
	keys := auditverify.Keys{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return keys, "no public keys in " + dir + ": signatures are not checked"
	}
	var bad []string
	for _, e := range entries {
		kid, ok := strings.CutSuffix(e.Name(), ".pub.pem")
		if !ok || e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err == nil {
			key, perr := auditverify.ParsePublicKeyPEM(data)
			if perr == nil {
				keys[kid] = key
				continue
			}
		}
		bad = append(bad, e.Name())
	}
	note := fmt.Sprintf("%d public key%s from %s", len(keys), plural(len(keys)), displayPath(dir))
	if len(bad) > 0 {
		note += "; unreadable: " + strings.Join(bad, ", ")
	}
	return keys, note
}

// openAudit switches to the audit pane, scoped to the session the reader was looking at when
// they came from the events or detail pane, and fetches the records.
func (m *model) openAudit() tea.Cmd {
	from := m.pane
	m.previousPane = from
	m.pane = paneAudit
	m.audit.detail = false
	m.audit.scopeTo = ""
	if from == paneEvents || from == paneDetail {
		m.audit.scopeTo = m.selectedSess
	}
	m.audit.session = m.audit.scopeTo
	if m.audit.keys == nil {
		m.audit.keys, m.audit.keyNote = loadAuditKeys(m.auditKeysDir())
	}
	m.rebuildAuditTable()
	return m.refreshAuditCmd()
}

// refreshAuditCmd refetches the records and, when there is one, the ledger.
func (m *model) refreshAuditCmd() tea.Cmd {
	return tea.Batch(m.loadAuditCmd(), m.loadLedgerCmd())
}

func (m *model) applyAuditPage(msg auditLoadedMsg) {
	m.audit.err = msg.err
	if msg.err != nil {
		return
	}
	m.audit.loaded = true
	m.audit.records = msg.page.Records
	if m.auditFile != nil {
		m.auditFile.gen = msg.fileGen
	}
	m.reverifyAudit()
	// A record the file viewer's store took after the page was read, and announced before the
	// page landed, was ignored then; it is read now.
	m.catchUpAuditFile()
}

// appendAuditRecord takes a record from the live stream. Ignored until the pane has loaded the
// stored records once, because a record verified without its predecessors would show a gap
// that is not one.
func (m *model) appendAuditRecord(r apiclient.AuditRecord) {
	m.appendAuditRecords([]apiclient.AuditRecord{r})
}

// appendAuditRecords appends records in order and verifies the set once.
func (m *model) appendAuditRecords(rs []apiclient.AuditRecord) {
	if !m.audit.loaded {
		return
	}
	added := false
	for _, r := range rs {
		if n := len(m.audit.records); n > 0 && r.Seq <= m.audit.records[n-1].Seq {
			continue // already have it from the fetch
		}
		m.audit.records = append(m.audit.records, r)
		added = true
	}
	if !added {
		return
	}
	if over := len(m.audit.records) - auditFetchLimit; over > 0 {
		m.audit.records = append([]apiclient.AuditRecord(nil), m.audit.records[over:]...)
	}
	m.reverifyAudit()
}

// reverifyAudit checks every record again. Links and gaps depend on the whole set, so one new
// record can change the verdict on another (a predecessor arriving after its successor).
func (m *model) reverifyAudit() {
	raw := make([][]byte, len(m.audit.records))
	for i, r := range m.audit.records {
		raw[i] = r.Record
	}
	m.audit.report = auditverify.Verify(raw, m.audit.keys)
	if m.pane == paneAudit {
		m.rebuildAuditTable()
	}
}

// auditFields is what a row shows of a record, read leniently: an edited record still renders.
type auditFields struct {
	Time        string `json:"time"`
	Action      string `json:"action"`
	Disposition string `json:"disposition"`
	StatusCode  string `json:"status_code"`
	Tool        struct {
		Name string `json:"name"`
	} `json:"tool"`
	Model struct {
		Name string `json:"name"`
	} `json:"ai_model"`
	Unmapped struct {
		Decision struct {
			Steps []struct {
				Plugin string `json:"plugin"`
			} `json:"steps"`
		} `json:"aid.decision"`
	} `json:"unmapped"`
}

func parseAuditFields(raw []byte) auditFields {
	var f auditFields
	_ = json.Unmarshal(raw, &f)
	return f
}

// target is what the call was made to: the tool, or for an inference call the model. The sink
// names the model only on a response record (ai_model, from the completion), so a request record
// takes it from its policy step, apl::llm::<model>::pre. A catch-all route's step names no model.
func (f auditFields) target() string {
	if f.Tool.Name != "" {
		return f.Tool.Name
	}
	if f.Model.Name != "" {
		return "model " + f.Model.Name
	}
	for _, s := range f.Unmapped.Decision.Steps {
		rest, ok := strings.CutPrefix(s.Plugin, "apl::llm::")
		if !ok {
			continue
		}
		model, _, _ := strings.Cut(rest, "::")
		if model == "*" {
			return "model (unlisted)"
		}
		return "model " + model
	}
	return ""
}

// phase names which ruling a record is, from the plugins its decision ran.
func (f auditFields) phase() string {
	var names []string
	for _, s := range f.Unmapped.Decision.Steps {
		names = append(names, s.Plugin)
	}
	joined := strings.Join(names, ",")
	switch {
	case strings.Contains(joined, "::pre"):
		return "authorize"
	case strings.Contains(joined, "::post"):
		return "response"
	case strings.Contains(joined, "jwt") || strings.Contains(joined, "identity"):
		return "identity"
	case strings.Contains(joined, "delegat") || strings.Contains(joined, "oauth"):
		return "token exchange"
	case joined == "":
		return "forward"
	}
	return joined
}

// verdict is what the record claims was decided: its action, the field an edit to turn a deny
// into an allow would change. Disposition is the fallback for a record without one. Modified is
// an allow that changed something on the way (a redaction, a session marked as having seen
// secret data), and says so.
func (f auditFields) verdict() string {
	switch {
	case f.Action == "Modified":
		return "Allowed (modified)"
	case f.Action != "":
		return f.Action
	}
	return f.Disposition
}

func (f auditFields) clock() string {
	t, err := time.Parse(time.RFC3339Nano, f.Time)
	if err != nil {
		return emptyCell
	}
	return t.Local().Format("15:04:05")
}

func integrityCell(r auditverify.Result) string {
	switch {
	case r.Err != nil:
		return "✗ unreadable"
	case r.Link == auditverify.LinkUnchained:
		return "– unsealed"
	case !r.FingerprintOK:
		return "✗ tampered"
	case r.Signature == auditverify.SignatureInvalid:
		return "✗ signature"
	case r.Signature == auditverify.SignatureValid:
		return "✓ signed"
	case r.Signature == auditverify.SignatureUnknownKey:
		return "? no key"
	}
	return "✓ hashed"
}

func chainCell(r auditverify.Result) string {
	switch r.Link {
	case auditverify.LinkIntact:
		return "✓ linked"
	case auditverify.LinkGenesis:
		return "● start"
	case auditverify.LinkBroken:
		return "✗ broken"
	case auditverify.LinkMissing:
		return "⚠ gap"
	}
	return "–"
}

// auditOrder is the records' display order: by epoch, stream and stream position, which is the
// order the engine stamped them in. Records with no stamp follow, in the order cortex took them.
func (m *model) auditOrder() []int {
	idx := make([]int, len(m.audit.records))
	for i := range idx {
		idx[i] = i
	}
	res := m.audit.report.Results
	sort.SliceStable(idx, func(a, b int) bool {
		sa, sb := res[idx[a]].Stamp, res[idx[b]].Stamp
		switch {
		case sa == nil && sb == nil:
			return m.audit.records[idx[a]].Seq < m.audit.records[idx[b]].Seq
		case sa == nil:
			return false
		case sb == nil:
			return true
		case sa.Epoch != sb.Epoch:
			return sa.Epoch < sb.Epoch
		case sa.StreamID != sb.StreamID:
			return sa.StreamID < sb.StreamID
		}
		return sa.StreamSeq < sb.StreamSeq
	})
	return idx
}

// rebuildAuditTable lays out the rows: records in stamp order, with a row for every run of
// missing stream positions and one where a new epoch starts. Gap rows are shown only unscoped:
// scoped to one session, the stream's other records are absent by choice, not lost.
func (m *model) rebuildAuditTable() {
	res := m.audit.report.Results
	if len(res) != len(m.audit.records) {
		m.auditTbl.SetRows(nil)
		m.audit.rows = nil
		return
	}
	var rows []table.Row
	var meta []auditRow
	var prev *auditverify.Stamp
	// One tool call yields several records (identity, authorize, response) and only the
	// authorize record names the tool; they share cortex's request id, so the others borrow it.
	toolOf := map[string]string{}
	for _, rec := range m.audit.records {
		if name := parseAuditFields(rec.Record).Tool.Name; name != "" && rec.RequestID != "" {
			toolOf[rec.RequestID] = name
		}
	}
	// A marker row spreads its words over the TOOL, PHASE and VERDICT columns, so no one
	// column's width cuts it off.
	marker := func(tool, phase, verdict string) table.Row {
		r := make(table.Row, len(auditColumns()))
		r[2], r[3], r[4] = tool, phase, verdict
		return r
	}
	for _, i := range m.auditOrder() {
		rec, r := m.audit.records[i], res[i]
		if m.audit.session != "" && rec.SessionID != m.audit.session {
			continue
		}
		if s := r.Stamp; s != nil && m.audit.session == "" {
			newStream := prev == nil || prev.Epoch != s.Epoch || prev.StreamID != s.StreamID
			if prev != nil && prev.Epoch != s.Epoch {
				rows = append(rows, marker("── NEW EPOCH ──", "restarted", "seq starts at 0"))
				meta = append(meta, auditRow{kind: auditRowEpoch})
			}
			var from uint64
			if !newStream {
				from = prev.StreamSeq + 1
			}
			if s.StreamSeq > from {
				span := fmt.Sprintf("seq %d", from)
				if s.StreamSeq-1 > from {
					span = fmt.Sprintf("seq %d–%d", from, s.StreamSeq-1)
				}
				rows = append(rows, marker(fmt.Sprintf("⚠ %d MISSING", s.StreamSeq-from), span,
					m.ledgerHolds(s.Epoch, s.StreamID, from, s.StreamSeq-1)))
				meta = append(meta, auditRow{kind: auditRowGap, rec: i,
					epoch: s.Epoch, stream: s.StreamID, from: from, to: s.StreamSeq - 1})
			}
			prev = s
		}
		// The identity filter hides the row only, after the markers above: a hidden record still
		// advances the stream, and an epoch it opens or a gap before it is still drawn.
		if m.audit.hideIdentity && m.auditHidden(rec, r) {
			continue
		}
		f := parseAuditFields(rec.Record)
		seq := emptyCell
		if r.Stamp != nil {
			seq = fmt.Sprint(r.Stamp.StreamSeq)
		}
		tool := f.target()
		if tool == "" {
			tool = toolOf[rec.RequestID]
		}
		if tool == "" {
			tool = emptyCell
		}
		session := rec.SessionID
		if session == "" {
			session = emptyCell
		}
		verdict := f.verdict()
		// A record the ledger disputes says what it claimed before, when the change is the verdict.
		for _, c := range m.ledgerChanges(i) {
			if c.Path == "action" && c.Was != "" {
				verdict += " (was " + strings.Trim(c.Was, `"`) + ")"
			}
		}
		rows = append(rows, table.Row{
			seq, f.clock(), tool, f.phase(), verdict,
			integrityCell(r), chainCell(r), m.receiptCell(r), session,
		})
		meta = append(meta, auditRow{kind: auditRowRecord, rec: i})
	}
	m.audit.rows = meta
	m.auditTbl.SetRows(rows)
	m.auditTbl.SetRowStyle(m.auditRowStyle)
	// The pane draws once before the fetch lands, with no rows, which leaves the cursor
	// before the first row; put it back on one, or Enter has nothing to open.
	if c := m.auditTbl.Cursor(); c < 0 || c >= len(rows) {
		setCursorVisible(&m.auditTbl, 0)
	}
}

// auditHidden reports whether the identity-rows filter leaves a record out: an identity check
// that passed every check. A record that is tampered, broken, after a gap, or that the ledger
// disagrees with is always shown, so the filter can never hide evidence.
func (m *model) auditHidden(rec apiclient.AuditRecord, r auditverify.Result) bool {
	if parseAuditFields(rec.Record).phase() != "identity" {
		return false
	}
	state, _ := m.receipt(r)
	return r.Err == nil && !r.Tampered() && r.Link != auditverify.LinkMissing && state != receiptDiffers
}

// auditRowStyle draws a tampered record and a gap in the error colour, and a record whose
// predecessor is missing or whose key agentop lacks in the warning colour.
func (m *model) auditRowStyle(row int) (lipgloss.Style, bool) {
	if row < 0 || row >= len(m.audit.rows) {
		return lipgloss.Style{}, false
	}
	meta := m.audit.rows[row]
	switch meta.kind {
	case auditRowGap:
		return styleError, true
	case auditRowEpoch:
		return styleHint, true
	}
	r := m.audit.report.Results[meta.rec]
	differs, _ := m.receipt(r)
	switch {
	case r.Err != nil || r.Tampered() || differs == receiptDiffers:
		return styleError, true
	case r.Link == auditverify.LinkMissing || r.Signature == auditverify.SignatureUnknownKey:
		return styleWarn, true
	}
	return lipgloss.Style{}, false
}

// nextFlaggedRow moves the cursor to the next row that needs a reader's attention: a tampered or
// unreadable record, a broken link, a record after a gap, a record the ledger disputes, or a gap
// marker. It wraps around, and stays put when nothing is flagged.
func (m *model) nextFlaggedRow() {
	n := len(m.audit.rows)
	start := m.auditTbl.Cursor()
	for step := 1; step <= n; step++ {
		row := (start + step) % n
		if st, styled := m.auditRowStyle(row); styled && st.GetForeground() != styleHint.GetForeground() {
			m.auditTbl.SetCursor(row)
			return
		}
	}
}

// auditSummary is the title's tally over the records in view.
func (m *model) auditSummary() string {
	var n, tampered, unchecked, differs int
	for _, meta := range m.audit.rows {
		if meta.kind != auditRowRecord {
			continue
		}
		n++
		r := m.audit.report.Results[meta.rec]
		if r.Err != nil || r.Tampered() {
			tampered++
		}
		if state, _ := m.receipt(r); state == receiptDiffers {
			differs++
		}
		if r.Signature == auditverify.SignatureUnsigned || r.Signature == auditverify.SignatureUnknownKey {
			unchecked++
		}
	}
	noun := "record"
	if m.audit.hideIdentity {
		noun = "decision"
	}
	parts := []string{fmt.Sprintf("%d %s%s", n, noun, plural(n))}
	if tampered > 0 {
		parts = append(parts, fmt.Sprintf("%d TAMPERED", tampered))
	}
	if differs > 0 {
		verb := "DIFFER"
		if differs == 1 {
			verb = "DIFFERS"
		}
		parts = append(parts, fmt.Sprintf("%d %s FROM THE LEDGER", differs, verb))
	}
	if g := len(m.audit.report.Gaps); g > 0 {
		parts = append(parts, fmt.Sprintf("%d gap%s", g, plural(g)))
	}
	if unchecked > 0 {
		parts = append(parts, fmt.Sprintf("%d not signature-checked", unchecked))
	}
	if l := m.ledgerTitle(); l != "" {
		parts = append(parts, l)
	}
	return strings.Join(parts, " · ")
}

// showAuditDetail opens the record under the cursor, and asks the ledger to verify its receipt
// when it has one.
func (m *model) showAuditDetail() tea.Cmd {
	c := m.auditTbl.Cursor()
	if c >= 0 && c < len(m.audit.rows) && m.audit.rows[c].kind == auditRowGap {
		return m.showGapDetail(m.audit.rows[c])
	}
	if c < 0 || c >= len(m.audit.rows) || m.audit.rows[c].kind != auditRowRecord {
		return nil
	}
	m.audit.detailGap = nil
	m.audit.detailRec = m.audit.rows[c].rec
	r := m.audit.report.Results[m.audit.detailRec]
	m.audit.proofUID, m.audit.proof, m.audit.proofErr, m.audit.proofDone = r.UID, ledger.Proof{}, nil, false
	m.renderAuditDetail()
	m.audit.vp.GotoTop()
	m.audit.detail = true
	if state, e := m.receipt(r); state == receiptMatches || state == receiptDiffers {
		return m.verifyProofCmd(r.UID, e)
	}
	return nil
}

// renderAuditDetail draws the open record: the verdict on each check, then the record.
func (m *model) renderAuditDetail() {
	if m.audit.detailGap != nil {
		m.renderGapDetail()
		return
	}
	i := m.audit.detailRec
	if i < 0 || i >= len(m.audit.records) || i >= len(m.audit.report.Results) {
		return
	}
	rec, r := m.audit.records[i], m.audit.report.Results[i]
	f := parseAuditFields(rec.Record)
	var b strings.Builder
	// Padded before it is coloured: escape codes inside the label would count toward the width.
	format := func(k, v string) string {
		if v == "" {
			v = emptyCell
		}
		return fmt.Sprintf("%-12s %s", k, v)
	}
	line := func(k, v string) { b.WriteString(format(k, v) + "\n") }
	alarm := func(k, v string) { b.WriteString(styleError.Render(format(k, v)) + "\n") }
	line("integrity", integrityCell(r))
	line("chain", chainCell(r))
	m.receiptDetail(r, line, alarm)
	if r.Stamp != nil {
		line("stream", fmt.Sprintf("%s  epoch %d  seq %d", r.Stamp.StreamID, r.Stamp.Epoch, r.Stamp.StreamSeq))
	}
	line("uid", r.UID)
	line("request", rec.RequestID)
	line("session", rec.SessionID)
	if f.StatusCode != "" {
		line("rule", f.StatusCode)
	}
	if r.Err != nil {
		line("error", r.Err.Error())
	}
	b.WriteString("\n")
	b.WriteString(ColorizeJSONBytes(rec.Record))
	m.audit.vp.SetContent(b.String())
}

// auditBody is the pane's title and body.
func (m *model) auditBody() (string, string) {
	scope := "all sessions"
	if m.audit.session != "" {
		scope = "session " + sanitizeLabel(m.audit.session)
	}
	title := fmt.Sprintf("%s · %s · audit · %s", m.appName(), m.endpoint, scope)
	if m.auditFile != nil {
		// No scope: the file viewer has no session to narrow to, and the title's width goes
		// to the tally after it, which is where a tampered record is counted.
		title = fmt.Sprintf("%s · audit · %s", m.appName(), m.endpoint)
	}
	switch {
	case m.audit.err != nil && !m.audit.loaded:
		return title, styleHint.Render("(audit records unavailable: " + m.audit.err.Error() +
			" — needs a cortex with session.audit on)")
	case m.auditFile != nil && len(m.audit.rows) == 0 && !m.audit.detail:
		// Not "yet" alone: the file may not exist, and the sink that writes it is not agentop's.
		return title, styleHint.Render("(no audit records in "+m.endpoint+" yet — waiting for the "+
			"policy engine's ocsf-audit sink to write them)") + "\n" + styleHint.Render(m.audit.keyNote)
	case !m.audit.loaded:
		return title, styleHint.Render("(loading audit records…)")
	case m.audit.detail:
		return title + " · record", m.audit.vp.View()
	case len(m.audit.rows) == 0:
		return title, styleHint.Render("(no audit records yet)") + "\n" + styleHint.Render(m.audit.keyNote)
	}
	return title + " · " + m.auditSummary(), m.auditTbl.View()
}

func (m *model) auditFooter() string {
	if m.audit.detail {
		return "[↑↓] scroll  [esc] back to records  [?] keys  [q] quit"
	}
	if m.auditFile != nil {
		identity := "  [i] hide identity checks"
		if m.audit.hideIdentity {
			identity = "  [i] show identity checks"
		}
		return "[↑↓] nav  [↵] record" + identity + "  [t] next flagged  [r] refresh  [?] keys  [q] quit"
	}
	scope := ""
	if m.audit.scopeTo != "" {
		scope = "  [s] this session / all"
	}
	identity := "  [i] hide identity checks"
	if m.audit.hideIdentity {
		identity = "  [i] show identity checks"
	}
	return "[↑↓] nav  [↵] record" + scope + identity + "  [r] refresh  [esc] back  [?] keys  [q] quit"
}

// handleAuditKey takes the pane's own keys; esc is handled with the other panes' back-outs.
func (m *model) handleAuditKey(msg tea.KeyMsg) tea.Cmd {
	if m.audit.detail {
		var cmd tea.Cmd
		m.audit.vp, cmd = m.audit.vp.Update(msg)
		return cmd
	}
	switch msg.String() {
	case "enter", "right", "l":
		return m.showAuditDetail()
	case "r":
		return m.refreshAuditCmd()
	case "t":
		m.nextFlaggedRow()
		return nil
	case "m":
		m.nextGapRow()
		return nil
	case "i":
		m.audit.hideIdentity = !m.audit.hideIdentity
		m.rebuildAuditTable()
		return nil
	case "s":
		if m.audit.scopeTo != "" {
			if m.audit.session == "" {
				m.audit.session = m.audit.scopeTo
			} else {
				m.audit.session = ""
			}
			m.rebuildAuditTable()
		}
		return nil
	}
	var cmd tea.Cmd
	m.auditTbl, cmd = m.auditTbl.Update(msg)
	return cmd
}
