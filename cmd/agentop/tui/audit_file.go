package tui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/rossoctl/cortex/cmd/agentop/apiclient"
	"github.com/rossoctl/cortex/core/audit"
)

// `agentop audit` shows the audit pane on its own, reading the records file directly instead of
// a cortex session API. It is for a proxy other than cortex that runs the same ocsf-audit sink
// (Praxis, say): the sink's file exporter writes the NDJSON file, and agentop follows it with
// the same store cortex uses to serve GET /v1/audit, so a record reaches the pane byte for byte
// as it would through cortex. Everything after the fetch is the observe viewer's own code:
// verification, gap and epoch rows, ledger receipts and the record detail.
//
// The store mirrors the file (audit.Store.Mirror): an edit to a record already shown, a deleted
// line or a replaced file reloads the pane from the file as it now is, so tampering shows the
// moment it happens.
//
// THE PANE IS THE WHOLE VIEWER IN THIS MODE. There is no server behind it, so every key that
// would leave the pane or ask a server something is refused (see auditFileKey), and the status
// line names the file rather than a connection.

// AuditFileOptions configures RunAuditFile.
type AuditFileOptions struct {
	// File is the records file the ocsf-audit sink's file exporter writes. It need not exist
	// yet: it is waited for, the way cortex waits for it.
	File string
	// KeysDir holds the signing authority's public keys, one <key id>.pub.pem per key. Empty
	// means auditKeysDir, where observe looks.
	KeysDir string
	// Ledger is the ARE ledger's gRPC address (host:port). Empty leaves receipts unchecked.
	Ledger string
	// Version names this build on the title bar.
	Version string
}

// auditFileSource is the store following the records file, and the subscription that tells the
// pane the file changed.
type auditFileSource struct {
	path  string
	store *audit.Store
	sub   *audit.Subscription
	// gen is the store generation the pane's records were read under. When the store's moves
	// on, the file was edited and the pane reloads rather than appends.
	gen uint64
}

// auditFileGrewMsg says the store took at least one new record, or dropped its records to read
// an edited file again. It carries neither: the handler reads what the store holds now, which
// also recovers records the subscription dropped when its buffer was full.
type auditFileGrewMsg struct{}

// RunAuditFile starts the audit pane on its own, following opts.File until ctx is done.
func RunAuditFile(ctx context.Context, opts AuditFileOptions) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	store := audit.New(0)
	defer store.Close()
	// Subscribed before the store starts reading, so no record lands between the first fetch
	// and the subscription unannounced.
	sub, unsubscribe := store.Subscribe()
	defer unsubscribe()
	go store.Mirror(ctx, opts.File)

	m := newAuditFileModel(ctx, &auditFileSource{path: opts.File, store: store, sub: sub}, opts)
	return runProgram(ctx, m)
}

// newAuditFileModel is a model pinned to the audit pane, fed by src.
func newAuditFileModel(ctx context.Context, src *auditFileSource, opts AuditFileOptions) *model {
	m := newPickerModel(ctx, nil, nil)
	m.pane = paneAudit
	m.previousPane = paneNone
	m.auditFile = src
	m.endpoint = displayPath(src.path)
	m.version = opts.Version
	m.audit.ledgerAddr = opts.Ledger
	m.audit.keysDir = opts.KeysDir
	m.audit.keys, m.audit.keyNote = loadAuditKeys(m.auditKeysDir())
	return m
}

// initAuditFile is Init for the audit-file viewer: the first read, the wait for more, and the
// ledger when there is one.
func (m *model) initAuditFile() tea.Cmd {
	cmds := []tea.Cmd{m.loadAuditCmd(), waitAuditFileCmd(m.auditFile.sub), m.loadLedgerCmd()}
	if m.audit.ledgerAddr != "" {
		cmds = append(cmds, refreshTickCmd())
	}
	return tea.Batch(cmds...)
}

// page is the file's answer to GET /v1/audit: the stored records, oldest first, at
// most auditFetchLimit, as the server pages them, and the store generation they belong to.
//
// The generation is read first. A reset between the two reads leaves it behind the records,
// which costs one more reload, never a stale page taken for a current one.
func (src *auditFileSource) page() (*apiclient.AuditPage, uint64) {
	gen := src.store.Generation()
	return &apiclient.AuditPage{
		Records: toAuditRecords(src.store.List("", 0, auditFetchLimit)),
		Skipped: src.store.Skipped(),
	}, gen
}

// waitAuditFileCmd blocks until the store takes a record or resets, then drains whatever else is
// queued so a burst is one message. Nil once the subscription is closed.
func waitAuditFileCmd(sub *audit.Subscription) tea.Cmd {
	return func() tea.Msg {
		select {
		case _, ok := <-sub.C:
			if !ok {
				return nil
			}
		case <-sub.Reset:
		}
		for {
			select {
			case _, ok := <-sub.C:
				if !ok {
					return auditFileGrewMsg{}
				}
			case <-sub.Reset:
			default:
				return auditFileGrewMsg{}
			}
		}
	}
}

// catchUpAuditFile brings the pane up to the store: it appends every stored record past the
// last one the pane holds or, when the file was edited since the pane read it, reloads it.
// Before the first load lands it does nothing: either that load read the store after the change,
// or the catch-up applyAuditPage runs after it does.
func (m *model) catchUpAuditFile() {
	if m.auditFile == nil || !m.audit.loaded {
		return
	}
	if m.auditFile.store.Generation() != m.auditFile.gen {
		page, gen := m.auditFile.page()
		m.auditFile.gen = gen
		m.audit.records = page.Records
		// The record open in the detail view may be gone or another one now.
		m.audit.detail = false
		m.reverifyAudit()
		m.setFlash("records file changed under the viewer: reread from the start")
		return
	}
	var after uint64
	if n := len(m.audit.records); n > 0 {
		after = m.audit.records[n-1].Seq
	}
	m.appendAuditRecords(toAuditRecords(m.auditFile.store.List("", after, 0)))
}

func toAuditRecords(in []audit.Record) []apiclient.AuditRecord {
	out := make([]apiclient.AuditRecord, len(in))
	for i, r := range in {
		out[i] = apiclient.AuditRecord{
			Seq:        r.Seq,
			ReceivedAt: r.ReceivedAt,
			RequestID:  r.RequestID,
			SessionID:  r.SessionID,
			Record:     r.Record,
		}
	}
	return out
}

// auditFileKey takes every key in the audit-file viewer that the search prompt and the help
// overlay have not. It reports whether it handled the key; one it did not goes on to the
// ordinary handling, which on the audit pane is the pane's own.
//
// AN ALLOWLIST, not a list of refusals: the global keys open panes and ask a server things, and a
// key added to them later must not start working here by default.
func (m *model) auditFileKey(msg tea.KeyMsg) (tea.Cmd, bool) {
	switch msg.String() {
	case "esc", "left", "h":
		// The record's detail closes; there is no pane behind the list to go back to.
		m.audit.detail = false
		return nil, true
	case "V":
		return m.refreshAuditCmd(), true
	case "q", "ctrl+c",
		"enter", "right", "l", "r", "i", "t", "m",
		"up", "down", "j", "k", "home", "end",
		"g", "G", "pgup", "pgdown", "pgdn", "b", "f":
		return nil, false
	}
	return nil, true
}

// auditFileStatus is the status line's left end in the audit-file viewer: the file followed, and
// how many of its lines were not records.
func (m *model) auditFileStatus() string {
	s := styleOK.Render("● following " + m.endpoint)
	if n := m.auditFile.store.Skipped(); n > 0 {
		s += styleWarn.Render(fmt.Sprintf("   %d line%s not a record", n, plural(int(n))))
	}
	return s
}

// displayPath shows a path under the home directory with ~, as loadAuditKeys does.
func displayPath(p string) string {
	if home, err := os.UserHomeDir(); err == nil {
		if rest, ok := strings.CutPrefix(filepath.Clean(p), home); ok && (rest == "" || rest[0] == filepath.Separator) {
			return "~" + rest
		}
	}
	return p
}
