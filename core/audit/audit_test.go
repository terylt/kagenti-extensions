package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// lines collects what a tailer hands on.
type lines struct {
	got     []string
	skipped []string
	resets  int
}

func (l *lines) tailer(path string) *tailer {
	return newTailer(path,
		func(b []byte) { l.got = append(l.got, string(b)) },
		func(r string) { l.skipped = append(l.skipped, r) })
}

func appendTo(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
}

func wantLines(t *testing.T, l *lines, want ...string) {
	t.Helper()
	if strings.Join(l.got, "|") != strings.Join(want, "|") {
		t.Fatalf("lines = %q, want %q", l.got, want)
	}
}

func TestTailerReadsCompleteLinesAndHoldsAPartialOne(t *testing.T) {
	path := filepath.Join(t.TempDir(), "records.ndjson")
	appendTo(t, path, "{\"a\":1}\n\n{\"b\":")
	l := &lines{}
	tl := l.tailer(path)
	tl.step()
	wantLines(t, l, `{"a":1}`)

	appendTo(t, path, "2}\n")
	tl.step()
	wantLines(t, l, `{"a":1}`, `{"b":2}`)
}

func TestTailerWaitsForAFileThatDoesNotExistYet(t *testing.T) {
	path := filepath.Join(t.TempDir(), "records.ndjson")
	l := &lines{}
	tl := l.tailer(path)
	tl.step()
	wantLines(t, l)
	appendTo(t, path, "{\"a\":1}\n")
	tl.step()
	wantLines(t, l, `{"a":1}`)
}

// A record written to the old file after the rename, before the writer
// reopens, is read before anything in the new file.
func TestTailerFollowsARenameRotationWithoutLosingTheOldTail(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "records.ndjson")
	rotated := path + ".1"
	appendTo(t, path, "{\"n\":1}\n")
	l := &lines{}
	tl := l.tailer(path)
	tl.step()

	if err := os.Rename(path, rotated); err != nil {
		t.Fatal(err)
	}
	appendTo(t, rotated, "{\"n\":2}\n")
	appendTo(t, path, "{\"n\":3}\n")
	tl.step()
	wantLines(t, l, `{"n":1}`, `{"n":2}`, `{"n":3}`)

	appendTo(t, path, "{\"n\":4}\n")
	tl.step()
	wantLines(t, l, `{"n":1}`, `{"n":2}`, `{"n":3}`, `{"n":4}`)
}

func TestTailerKeepsReadingARenamedFileUntilAReplacementAppears(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "records.ndjson")
	appendTo(t, path, "{\"n\":1}\n")
	l := &lines{}
	tl := l.tailer(path)
	tl.step()
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	appendTo(t, path+".1", "{\"n\":2}\n")
	tl.step()
	wantLines(t, l, `{"n":1}`, `{"n":2}`)
}

func TestTailerStartsOverWhenTheFileIsTruncatedInPlace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "records.ndjson")
	appendTo(t, path, "{\"n\":1}\n{\"n\":2}\n")
	l := &lines{}
	tl := l.tailer(path)
	tl.step()
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	appendTo(t, path, "{\"n\":3}\n")
	tl.step()
	wantLines(t, l, `{"n":1}`, `{"n":2}`, `{"n":3}`)
}

func TestTailerSkipsAnOverlongLineAndRecovers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "records.ndjson")
	appendTo(t, path, strings.Repeat("x", maxLineBytes+10)+"\n{\"ok\":1}\n")
	l := &lines{}
	tl := l.tailer(path)
	tl.step()
	wantLines(t, l, `{"ok":1}`)
	if len(l.skipped) != 1 {
		t.Fatalf("skipped = %q, want one", l.skipped)
	}
}

// mirror is a mirroring tailer that counts its resets in l.resets.
func (l *lines) mirror(path string) *tailer {
	return newMirrorTailer(path,
		func(b []byte) { l.got = append(l.got, string(b)) },
		func(r string) { l.skipped = append(l.skipped, r) },
		func() { l.got = nil; l.resets++ })
}

// rewriteInPlace overwrites path from the start without changing the file,
// as an editor holding it open does, and moves its modification time on so
// a coarse clock cannot hide the write.
func rewriteInPlace(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte(s), 0); err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(int64(len(s))); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(time.Second)
	if err := os.Chtimes(path, later, later); err != nil {
		t.Fatal(err)
	}
}

// An edit that leaves the file longer than what was read is no truncation,
// and a log tailer would read on from its offset; a mirror reads it again.
func TestMirrorStartsOverWhenTheFileIsRewrittenInPlace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "records.ndjson")
	appendTo(t, path, "{\"action\":\"Denied\"}\n{\"n\":2}\n")
	l := &lines{}
	tl := l.mirror(path)
	tl.step()
	rewriteInPlace(t, path, "{\"action\":\"Allowed\"}\n{\"n\":2}\n{\"n\":3}\n")
	tl.step()
	wantLines(t, l, `{"action":"Allowed"}`, `{"n":2}`, `{"n":3}`)
	if l.resets != 1 {
		t.Fatalf("resets = %d, want 1", l.resets)
	}
}

func TestMirrorStartsOverWhenTheFileIsReplaced(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "records.ndjson")
	appendTo(t, path, "{\"n\":1}\n{\"n\":2}\n")
	l := &lines{}
	tl := l.mirror(path)
	tl.step()
	appendTo(t, path+".new", "{\"n\":1}\n")
	if err := os.Rename(path+".new", path); err != nil {
		t.Fatal(err)
	}
	tl.step()
	wantLines(t, l, `{"n":1}`)
	if l.resets != 1 {
		t.Fatalf("resets = %d, want 1", l.resets)
	}
}

func TestMirrorStartsOverWhenTheFileIsTruncated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "records.ndjson")
	appendTo(t, path, "{\"n\":1}\n{\"n\":2}\n")
	l := &lines{}
	tl := l.mirror(path)
	tl.step()
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	tl.step()
	wantLines(t, l)
	if l.resets != 1 {
		t.Fatalf("resets = %d, want 1", l.resets)
	}
}

// Appends move the modification time too; the sum tells them from an edit.
func TestMirrorReadsAppendsWithoutStartingOver(t *testing.T) {
	path := filepath.Join(t.TempDir(), "records.ndjson")
	appendTo(t, path, "{\"n\":1}\n{\"n\":")
	l := &lines{}
	tl := l.mirror(path)
	tl.step()
	appendTo(t, path, "2}\n")
	later := time.Now().Add(time.Second)
	if err := os.Chtimes(path, later, later); err != nil {
		t.Fatal(err)
	}
	tl.step()
	wantLines(t, l, `{"n":1}`, `{"n":2}`)
	if l.resets != 0 {
		t.Fatalf("resets = %d, want 0", l.resets)
	}
}

func TestMirrorStoreDropsItsRecordsAndSignalsAReset(t *testing.T) {
	s := New(0)
	sub, cancel := s.Subscribe()
	defer cancel()
	s.appendLine([]byte(record("r", "s")))
	s.appendLine([]byte("not json"))
	s.reset()
	select {
	case <-sub.Reset:
	default:
		t.Fatal("no reset signal")
	}
	if got := s.List("", 0, 0); len(got) != 0 {
		t.Fatalf("records kept across a reset: %+v", got)
	}
	if s.Generation() != 1 || s.Skipped() != 0 {
		t.Fatalf("generation = %d, skipped = %d; want 1, 0", s.Generation(), s.Skipped())
	}
	// A slow subscriber's signals coalesce rather than block.
	s.reset()
	s.reset()
	s.appendLine([]byte(record("r", "s")))
	if got := s.List("", 0, 0); len(got) != 1 || got[0].Seq != 2 {
		t.Fatalf("after the reset: %+v, want one record at Seq 2", got)
	}
}

func record(requestID, sessionID string) string {
	return `{"class_uid":6003,"ai_agent":{"instance_uid":"` + sessionID +
		`"},"unmapped":{"cmf.request.request_id":"` + requestID + `"}}`
}

func TestStoreIndexesTheJoinKeysAndKeepsBytes(t *testing.T) {
	s := New(0)
	raw := record("1-abc", "claude-1")
	s.appendLine([]byte(raw))
	got := s.List("", 0, 0)
	if len(got) != 1 || got[0].Seq != 1 || got[0].RequestID != "1-abc" || got[0].SessionID != "claude-1" {
		t.Fatalf("records = %+v", got)
	}
	if string(got[0].Record) != raw {
		t.Fatalf("bytes changed:\n got %s\nwant %s", got[0].Record, raw)
	}
}

func TestStoreKeepsARecordWhoseFieldsHaveUnexpectedTypes(t *testing.T) {
	s := New(0)
	s.appendLine([]byte(`{"ai_agent":"tampered","unmapped":7}`))
	if got := s.List("", 0, 0); len(got) != 1 || got[0].SessionID != "" {
		t.Fatalf("records = %+v", got)
	}
}

func TestStoreSkipsLinesThatAreNotRecords(t *testing.T) {
	s := New(0)
	for _, line := range []string{"not json", "[1,2]", `"str"`, `{"a":`} {
		s.appendLine([]byte(line))
	}
	if got := s.List("", 0, 0); len(got) != 0 {
		t.Fatalf("records = %+v", got)
	}
	if s.Skipped() != 4 {
		t.Fatalf("skipped = %d, want 4", s.Skipped())
	}
}

func TestStoreListFiltersBySessionAndPages(t *testing.T) {
	s := New(0)
	for _, sess := range []string{"a", "b", "a", "a"} {
		s.appendLine([]byte(record("r", sess)))
	}
	if got := s.List("a", 0, 0); len(got) != 3 {
		t.Fatalf("session a: %d records", len(got))
	}
	got := s.List("a", 1, 1)
	if len(got) != 1 || got[0].Seq != 3 {
		t.Fatalf("after 1, limit 1: %+v", got)
	}
}

func TestStoreKeepsOnlyTheNewestRecords(t *testing.T) {
	s := New(2)
	for i := 0; i < 5; i++ {
		s.appendLine([]byte(record("r", "s")))
	}
	got := s.List("", 0, 0)
	if len(got) != 2 || got[0].Seq != 4 || got[1].Seq != 5 {
		t.Fatalf("records = %+v", got)
	}
}

func TestSubscribersGetNewRecordsAndASlowOneNeverBlocks(t *testing.T) {
	s := New(0)
	sub, cancel := s.Subscribe()
	defer cancel()
	slow, cancelSlow := s.Subscribe()
	defer cancelSlow()

	done := make(chan struct{})
	go func() {
		for i := 0; i < subscriberChanBuf+50; i++ {
			s.appendLine([]byte(record("r", "s")))
			<-sub.C
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("append blocked on a slow subscriber")
	}
	if slow.Drops() != 50 {
		t.Fatalf("slow subscriber drops = %d, want 50", slow.Drops())
	}
}

func TestCloseEndsSubscriptions(t *testing.T) {
	s := New(0)
	sub, cancel := s.Subscribe()
	s.Close()
	if _, open := <-sub.C; open {
		t.Fatal("subscription still open after Close")
	}
	cancel()
	s.appendLine([]byte(record("r", "s")))
	if got := s.List("", 0, 0); len(got) != 0 {
		t.Fatalf("records appended after Close: %+v", got)
	}
}
