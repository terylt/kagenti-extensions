package tui

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/rossoctl/cortex/cmd/agentop/apiclient"
	"github.com/rossoctl/cortex/core/audit"
)

// auditFileModel is the audit-file viewer over a records file holding records, its store
// following the file until the test ends.
func auditFileModel(t *testing.T, records []apiclient.AuditRecord) (*model, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "records.ndjson")
	writeAuditLines(t, path, records...)
	ctx, cancel := context.WithCancel(context.Background())
	store := audit.New(0)
	sub, unsubscribe := store.Subscribe()
	go store.Mirror(ctx, path)
	t.Cleanup(func() {
		cancel()
		unsubscribe()
		store.Close()
	})
	m := newAuditFileModel(ctx, &auditFileSource{path: path, store: store, sub: sub}, AuditFileOptions{File: path})
	m.width, m.height = 160, 40
	m.layout()
	waitForStored(t, store, len(records))
	return m, path
}

func writeAuditLines(t *testing.T, path string, records ...apiclient.AuditRecord) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, r := range records {
		if _, err := f.Write(append(append([]byte(nil), r.Record...), '\n')); err != nil {
			t.Fatal(err)
		}
	}
}

// waitFor waits for the store's tailer, which polls, to reach a state.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("the store did not reach the state within 5s")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// waitForStored waits for the store's tailer, which polls, to have read n records.
func waitForStored(t *testing.T, store *audit.Store, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for len(store.List("", 0, 0)) < n {
		if time.Now().After(deadline) {
			t.Fatalf("store holds %d records, want %d", len(store.List("", 0, 0)), n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// load runs the viewer's first fetch through Update, as Init's command would.
func load(m *model) {
	m.Update(m.loadAuditCmd()())
}

// The viewer reads the file through the same store cortex serves from, and verifies what it
// reads with the observe pane's own checks.
func TestAuditFile_ReadsAndVerifiesTheFile(t *testing.T) {
	m, _ := auditFileModel(t, auditFixture(t))
	if m.pane != paneAudit {
		t.Fatalf("pane = %v, want audit", m.pane)
	}
	load(m)
	if got := strings.Join(cells(m, colIntegrity), "|"); got != "✓ signed|✓ signed|✓ signed" {
		t.Errorf("integrity = %s", got)
	}
	if got := strings.Join(cells(m, colChain), "|"); got != "● start|✓ linked|✓ linked" {
		t.Errorf("chain = %s", got)
	}
}

// A record the sink appends reaches the pane through the subscription, and is verified with the
// records before it.
func TestAuditFile_FollowsAppends(t *testing.T) {
	records := auditFixture(t)
	m, path := auditFileModel(t, records[:2])
	load(m)

	writeAuditLines(t, path, records[2])
	// The subscription also holds the first two records' notices, so the wait can return before
	// the tailer reads the third; the catch-up it triggers reads whatever the store holds.
	waitForStored(t, m.auditFile.store, 3)
	msg := waitMsg(t, waitAuditFileCmd(m.auditFile.sub))
	if _, ok := msg.(auditFileGrewMsg); !ok {
		t.Fatalf("msg = %T, want auditFileGrewMsg", msg)
	}
	if _, cmd := m.Update(msg); cmd == nil {
		t.Error("the wait for the next append was not re-armed")
	}
	if got := strings.Join(cells(m, colChain), "|"); got != "● start|✓ linked|✓ linked" {
		t.Errorf("chain after the append = %s", got)
	}
}

// An append announced before the first load lands is ignored then, and still shown: the load's
// own catch-up reads it. Without that the record would wait for the next append to appear.
func TestAuditFile_AnAppendRacingTheFirstLoadIsNotLost(t *testing.T) {
	records := auditFixture(t)
	m, path := auditFileModel(t, records[:2])
	page := m.loadAuditCmd()() // read before the append

	writeAuditLines(t, path, records[2])
	waitForStored(t, m.auditFile.store, 3)
	m.Update(auditFileGrewMsg{}) // announced before the page lands
	if m.audit.loaded {
		t.Fatal("loaded before the page landed")
	}
	m.Update(page)
	if n := len(m.audit.records); n != 3 {
		t.Errorf("records = %d, want 3", n)
	}
}

// An insider's edit to the live file shows in the open pane: the deny flipped to an allow in
// place, with nothing appended, is read again and flagged, and the flash says why the rows moved.
func TestAuditFile_AnEditInPlaceShowsAsItHappens(t *testing.T) {
	m, path := auditFileModel(t, auditFixture(t))
	load(m)
	gen := m.auditFile.store.Generation()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	edited := bytes.Replace(raw, []byte(`"action":"Denied"`), []byte(`"action":"Allowed"`), 1)
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(edited, 0); err != nil {
		t.Fatal(err)
	}
	f.Close()
	later := time.Now().Add(time.Second)
	if err := os.Chtimes(path, later, later); err != nil {
		t.Fatal(err)
	}

	msg := waitMsg(t, waitAuditFileCmd(m.auditFile.sub))
	waitFor(t, func() bool {
		return m.auditFile.store.Generation() != gen && len(m.auditFile.store.List("", 0, 0)) == 3
	})
	m.Update(msg)
	if got := strings.Join(cells(m, colIntegrity), "|"); got != "✓ signed|✗ tampered|✓ signed" {
		t.Errorf("integrity after the edit = %s", got)
	}
	if !strings.Contains(m.flash, "reread") {
		t.Errorf("flash = %q", m.flash)
	}
	if n := len(m.audit.records); n != 3 {
		t.Errorf("records = %d, want 3: an edit reloads, it does not append", n)
	}
}

// A deleted line shows as the gap it leaves, without restarting the viewer.
func TestAuditFile_ADeletedRecordShowsAsItHappens(t *testing.T) {
	records := auditFixture(t)
	m, path := auditFileModel(t, records)
	load(m)
	gen := m.auditFile.store.Generation()

	tmp := path + ".tmp"
	writeAuditLines(t, tmp, records[0], records[2])
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
	msg := waitMsg(t, waitAuditFileCmd(m.auditFile.sub))
	waitFor(t, func() bool {
		return m.auditFile.store.Generation() != gen && len(m.auditFile.store.List("", 0, 0)) == 2
	})
	m.Update(msg)
	if n := len(m.audit.records); n != 2 {
		t.Fatalf("records = %d, want 2", n)
	}
	if got := strings.Join(cells(m, colChain), "|"); got != "● start||⚠ gap" {
		t.Errorf("chain after the deletion = %s", got)
	}
}

// Every key that would leave the pane or ask a server something does nothing here: the pane
// stays, and nothing dereferences the client the viewer does not have.
func TestAuditFile_KeysThatLeaveThePaneAreInert(t *testing.T) {
	m, _ := auditFileModel(t, auditFixture(t))
	load(m)
	for _, k := range []tea.KeyMsg{
		key('u'), key('P'), key('C'), key('A'), key('$'), key('S'), key('X'), key('x'),
		key('e'), key('y'), key('o'), key('p'), key('s'), key('c'), key('w'), key('a'),
		{Type: tea.KeyEsc}, {Type: tea.KeyLeft},
	} {
		m.handleKey(k)
		if m.pane != paneAudit {
			t.Fatalf("%q moved the viewer to pane %v", k.String(), m.pane)
		}
		if m.clearConfirm != nil || m.serverPicker != nil || m.editState.phase != editPhaseDone {
			t.Fatalf("%q opened a dialog the viewer cannot serve", k.String())
		}
	}
}

// The pane's own keys work as in observe: Enter opens a record, esc closes it, and V refetches.
func TestAuditFile_ThePanesKeysWork(t *testing.T) {
	m, _ := auditFileModel(t, auditFixture(t))
	load(m)
	m.handleKey(key('j'))
	if c := m.auditTbl.Cursor(); c != 1 {
		t.Errorf("j: cursor = %d, want 1", c)
	}
	m.handleKey(tea.KeyMsg{Type: tea.KeyEnter})
	if !m.audit.detail {
		t.Fatal("enter did not open the record")
	}
	m.handleKey(tea.KeyMsg{Type: tea.KeyEsc})
	if m.audit.detail || m.pane != paneAudit {
		t.Fatalf("esc: detail = %v, pane = %v", m.audit.detail, m.pane)
	}
	if cmd := m.handleKey(key('V')); cmd == nil {
		t.Error("V did not refetch")
	}
	if cmd := m.handleKey(key('q')); cmd == nil {
		t.Error("q did not quit")
	}
}

// The status line names the file, not a connection the viewer does not have, and no spend band
// is drawn for a proxy it cannot ask.
func TestAuditFile_StatusNamesTheFile(t *testing.T) {
	m, path := auditFileModel(t, auditFixture(t))
	load(m)
	view := m.View()
	if !strings.Contains(view, "following "+displayPath(path)) {
		t.Errorf("status does not name the file:\n%s", view)
	}
	for _, unwanted := range []string{"connecting", "events/sec", "[esc] back"} {
		if strings.Contains(view, unwanted) {
			t.Errorf("view says %q:\n%s", unwanted, view)
		}
	}
	if m.spendStripReservesRow() {
		t.Error("a spend band row is reserved")
	}
}

// A file the sink has not written yet is waited for, and the pane says what it is waiting for.
func TestAuditFile_AMissingFileIsWaitedFor(t *testing.T) {
	m, path := auditFileModel(t, nil)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	load(m)
	if _, body := m.auditBody(); !strings.Contains(body, "waiting for the policy engine's ocsf-audit sink") {
		t.Errorf("body = %q", body)
	}
}

// The help shows this pane's keys and none of the jumps to panes the viewer cannot reach.
func TestAuditFile_HelpListsOnlyThisViewersKeys(t *testing.T) {
	body := helpBodyAuditFile(100)
	for _, unwanted := range []string{jumpSectionTitle, drillSectionTitle, everyPaneTitle, "this session / all"} {
		if strings.Contains(body, unwanted) {
			t.Errorf("help says %q:\n%s", unwanted, body)
		}
	}
	// The letter keys the help lists reach the pane's handler rather than being swallowed.
	m := &model{}
	for _, k := range []rune{'i', 't', 'm', 'r', 'q', 'j', 'k', 'g', 'G'} {
		if _, handled := m.auditFileKey(key(k)); handled {
			t.Errorf("help lists %q, which auditFileKey swallows", k)
		}
	}
}

// --keys picks the directory public keys are read from.
func TestAuditFile_KeysDirOverridesTheDefault(t *testing.T) {
	records := auditFixture(t) // keys under $HOME/.cortex/audit/keys
	dir := filepath.Join(os.Getenv("HOME"), ".cortex", "audit", "keys")
	t.Setenv("HOME", t.TempDir()) // the default now holds none
	path := filepath.Join(t.TempDir(), "records.ndjson")
	writeAuditLines(t, path, records...)
	store := audit.New(0)
	sub, unsubscribe := store.Subscribe()
	defer unsubscribe()
	m := newAuditFileModel(context.Background(), &auditFileSource{path: path, store: store, sub: sub},
		AuditFileOptions{File: path, KeysDir: dir})
	if len(m.audit.keys) != 1 {
		t.Errorf("keys = %d from %s, want 1 (%s)", len(m.audit.keys), dir, m.audit.keyNote)
	}
}

func waitMsg(t *testing.T, cmd tea.Cmd) tea.Msg {
	t.Helper()
	ch := make(chan tea.Msg, 1)
	go func() { ch <- cmd() }()
	select {
	case msg := <-ch:
		return msg
	case <-time.After(5 * time.Second):
		t.Fatal("no message within 5s")
		return nil
	}
}
