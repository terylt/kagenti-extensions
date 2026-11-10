package audit

import (
	"bytes"
	"context"
	"errors"
	"hash/crc32"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"time"
)

// maxLineBytes bounds one record. A longer line is skipped and counted, not
// held, so a runaway writer cannot grow the tailer's buffer without limit.
const maxLineBytes = 1 << 20

// defaultPollInterval is how often the tailer looks for new bytes and for a
// rotation. Polling rather than fsnotify keeps one code path for a file that
// does not exist yet, one that is appended to, one renamed away and one
// truncated in place, and a stat a few times a second costs nothing.
const defaultPollInterval = 200 * time.Millisecond

// tailer follows an append-only NDJSON file by name, the way `tail -F` does:
//
//   - It starts at the beginning, so a restart reloads what is on disk.
//   - It hands on complete lines only; a partial last line waits for its
//     newline.
//   - When the path names a different file (a rotator renamed the old one
//     away), it reads the old file to its end, then switches to the new one
//     from the start, so nothing written before the rotation is skipped.
//   - When the file shrinks under it (truncated in place), it starts over
//     from the beginning of the same file.
//   - A path that does not exist yet is waited for.
//
// A mirroring tailer (onReset set) follows the file as it is now rather than
// as a log: when the bytes it already read change, it calls onReset and reads
// the file again from the start. See newMirrorTailer.
type tailer struct {
	path    string
	poll    time.Duration
	onLine  func([]byte)
	onSkip  func(reason string)
	onReset func()
	f       *os.File
	offset  int64
	partial []byte
	// discarding is true while the rest of an over-long line is skipped.
	discarding bool

	// What a mirroring tailer checks the file against. opened is true once a
	// file has been read, so the next one opened replaces it. sum is the
	// CRC-32C of bytes [0, offset), and modTime the held file's modification
	// time when they were last read.
	opened  bool
	sum     uint32
	modTime time.Time
}

func newTailer(path string, onLine func([]byte), onSkip func(string)) *tailer {
	return &tailer{path: path, poll: defaultPollInterval, onLine: onLine, onSkip: onSkip}
}

// newMirrorTailer is a tailer that also starts over, calling onReset first,
// when the file is replaced (renamed over or recreated), truncated, or
// rewritten in place. The last needs no truncation to be seen: when the
// modification time moves, the bytes already read are summed again and
// compared. The sum is a change detector for a viewer, not an integrity
// check; the records carry their own.
func newMirrorTailer(path string, onLine func([]byte), onSkip func(string), onReset func()) *tailer {
	t := newTailer(path, onLine, onSkip)
	t.onReset = onReset
	return t
}

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// run follows the file until ctx is done.
func (t *tailer) run(ctx context.Context) {
	ticker := time.NewTicker(t.poll)
	defer ticker.Stop()
	defer t.close()
	for {
		t.step()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// step reads whatever is new and follows a rotation or truncation. Exposed
// to tests so they need not wait on the ticker.
func (t *tailer) step() {
	if t.f == nil {
		f, err := os.Open(t.path)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				slog.Warn("audit: cannot open records file", "path", t.path, "error", err)
			}
			return
		}
		t.f = f
		t.rewind()
		if t.opened && t.onReset != nil {
			// A replacement, not a continuation: what was read came from
			// another file.
			t.onReset()
		}
		t.opened = true
	}

	held, err := t.f.Stat()
	if err != nil {
		t.close()
		return
	}
	switch {
	case held.Size() < t.offset:
		// Truncated in place: the bytes we had read are gone, so is any
		// partial line built from them.
		t.rewind()
		if t.onReset != nil {
			t.onReset()
		}
	case t.onReset != nil && t.offset > 0 && !held.ModTime().Equal(t.modTime) && t.rewritten():
		// Rewritten in place without shrinking past what was read.
		t.rewind()
		t.onReset()
	}
	// The time is taken before the read, so a write during it moves the
	// time again and is checked on the next step.
	t.modTime = held.ModTime()
	t.drain()

	current, err := os.Stat(t.path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// Renamed away with no replacement yet; keep reading the old file.
	case err != nil:
	case !os.SameFile(held, current):
		// Rotated: the old file is drained above, so switch to the new one.
		t.close()
		t.step()
	}
}

// rewind forgets what was read from the held file, to read it again from
// the start.
func (t *tailer) rewind() {
	t.offset, t.partial, t.discarding, t.sum = 0, nil, false, 0
}

// rewritten reports whether bytes [0, offset) of the held file no longer
// sum to what was read there.
func (t *tailer) rewritten() bool {
	h := crc32.New(castagnoli)
	n, err := io.Copy(h, io.NewSectionReader(t.f, 0, t.offset))
	if err != nil || n != t.offset {
		return true
	}
	return h.Sum32() != t.sum
}

// drain reads from offset to the end of the held file.
func (t *tailer) drain() {
	if _, err := t.f.Seek(t.offset, io.SeekStart); err != nil {
		return
	}
	buf := make([]byte, 64<<10)
	for {
		n, err := t.f.Read(buf)
		if n > 0 {
			t.offset += int64(n)
			if t.onReset != nil {
				t.sum = crc32.Update(t.sum, castagnoli, buf[:n])
			}
			t.consume(buf[:n])
		}
		if err != nil {
			return
		}
	}
}

func (t *tailer) consume(chunk []byte) {
	for len(chunk) > 0 {
		i := bytes.IndexByte(chunk, '\n')
		if i < 0 {
			t.hold(chunk)
			return
		}
		t.hold(chunk[:i])
		if t.discarding {
			t.discarding = false
		} else if len(t.partial) > 0 {
			line := t.partial
			t.partial = nil
			t.onLine(line)
		}
		chunk = chunk[i+1:]
	}
}

// hold appends to the partial line, or starts discarding when it would pass
// maxLineBytes.
func (t *tailer) hold(b []byte) {
	if t.discarding {
		return
	}
	if len(t.partial)+len(b) > maxLineBytes {
		t.partial, t.discarding = nil, true
		t.onSkip("line longer than 1 MiB")
		return
	}
	t.partial = append(t.partial, b...)
}

func (t *tailer) close() {
	if t.f != nil {
		_ = t.f.Close()
		t.f = nil
	}
}
