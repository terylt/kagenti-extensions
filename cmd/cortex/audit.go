package main

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/rossoctl/cortex/core/audit"
	"github.com/rossoctl/cortex/core/config"
)

// auditDirName and auditFileName place the records file the policy engine's ocsf-audit sink
// appends to: always ~/.cortex/audit/records.ndjson. There is no config for it, because in this
// release session.audit is a laptop feature — see config.SessionAuditConfig.
const (
	auditDirName  = "audit"
	auditFileName = "records.ndjson"
)

func auditRecordsPath() (string, error) {
	dir, err := defaultCortexDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, auditDirName, auditFileName), nil
}

// auditRuns reports whether cortex follows the audit records file: session.audit.enabled on a
// local install.
func auditRuns(c *config.Config, localInstall bool) bool {
	return localInstall && c.Session.Audit.AuditEnabled()
}

// ensureAuditDir creates ~/.cortex/audit, owner-only, when the audit store runs. It is called
// before the plugins build, on startup and on every reload, because the sink's file exporter
// opens its file when the cpex plugin initializes and fails the load if the directory is
// missing.
func ensureAuditDir(c *config.Config, localInstall bool) {
	if !auditRuns(c, localInstall) {
		return
	}
	path, err := auditRecordsPath()
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		slog.Warn("session.audit: cannot create the records directory", "dir", filepath.Dir(path), "error", err)
	}
}

// openAuditStore starts following the records file when session.audit is on, and returns the
// store and the function that stops it. Off, it returns nil and a no-op. A failure is a warning,
// not a fatal error: the audit view is observability, and the sink keeps writing the file either
// way.
func openAuditStore(c *config.Config, localInstall bool) (*audit.Store, func()) {
	noop := func() {}
	if !c.Session.Audit.AuditEnabled() {
		return nil, noop
	}
	if !localInstall {
		slog.Warn("session.audit will NOT run despite session.audit.enabled: true",
			"reason", "the audit view is a laptop feature in this release and runs only from a config inside ~/.cortex")
		return nil, noop
	}
	path, err := auditRecordsPath()
	if err != nil {
		slog.Warn("session.audit disabled — cannot determine where the records file is", "error", err)
		return nil, noop
	}
	store := audit.New(c.Session.Audit.MaxRecords)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		store.Follow(ctx, path)
	}()
	slog.Info("session.audit enabled — serving signed audit records on GET /v1/audit",
		"file", path, "note", "cortex serves the records; agentop verifies them")
	return store, func() {
		cancel()
		<-done
		store.Close()
	}
}
