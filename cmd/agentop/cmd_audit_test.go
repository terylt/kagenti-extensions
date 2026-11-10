package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

// With no --file the viewer follows the file a local cortex's sink writes.
func TestParseAuditFlags_DefaultsToTheCortexRecordsFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	opts, _, ok := parseAuditFlags(nil, &bytes.Buffer{})
	if !ok {
		t.Fatal("no flags was refused")
	}
	if want := filepath.Join(home, ".cortex", "audit", "records.ndjson"); opts.File != want {
		t.Errorf("file = %q, want %q", opts.File, want)
	}
	if opts.KeysDir != "" || opts.Ledger != "" {
		t.Errorf("keys = %q, ledger = %q, want both empty", opts.KeysDir, opts.Ledger)
	}
}

func TestParseAuditFlags_TakesFileKeysAndLedger(t *testing.T) {
	opts, _, ok := parseAuditFlags([]string{"--file", "/tmp/r.ndjson", "--keys", "/tmp/k", "--ledger", "localhost:50051"}, &bytes.Buffer{})
	if !ok {
		t.Fatal("refused")
	}
	if opts.File != "/tmp/r.ndjson" || opts.KeysDir != "/tmp/k" || opts.Ledger != "localhost:50051" {
		t.Errorf("opts = %+v", opts)
	}
}

// A bare path is the likely mistake, and naming --file is the fix.
func TestParseAuditFlags_RefusesAPositionalPath(t *testing.T) {
	var stderr bytes.Buffer
	_, code, ok := parseAuditFlags([]string{"records.ndjson"}, &stderr)
	if ok || code != 2 {
		t.Fatalf("ok = %v, code = %d, want refused with 2", ok, code)
	}
	if !strings.Contains(stderr.String(), "--file") {
		t.Errorf("stderr does not name --file: %q", stderr.String())
	}
}

func TestParseAuditFlags_HelpExitsZero(t *testing.T) {
	var stderr bytes.Buffer
	_, code, ok := parseAuditFlags([]string{"--help"}, &stderr)
	if ok || code != 0 {
		t.Fatalf("ok = %v, code = %d, want 0", ok, code)
	}
	if !strings.Contains(stderr.String(), "agentop audit [--file PATH]") {
		t.Errorf("usage missing:\n%s", stderr.String())
	}
}
