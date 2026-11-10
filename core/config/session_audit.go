package config

import "fmt"

// SessionAuditConfig is `session.audit`: cortex follows the signed OCSF audit records the
// policy engine's ocsf-audit sink writes, and serves them on the session API (GET /v1/audit and
// `audit-record` events on GET /v1/events) for agentop to verify and show.
//
// A LAPTOP FEATURE IN THIS RELEASE, like the session archive. The cortex binary follows the file
// only when started from a config inside ~/.cortex, and the file is always
// ~/.cortex/audit/records.ndjson; there is deliberately no path. The cpex policy names the same
// path in the sink's `file` exporter.
//
// OFF BY DEFAULT. It needs a cortex build that carries the audit sink and a policy that
// configures it; turning it on without them serves an empty list.
//
// Nested under `session` because it is served by the session API, and because
// reloader.validateReloadable refuses any live change under `session`, so changing it needs a
// restart with no code of its own.
type SessionAuditConfig struct {
	// Enabled is a pointer so an explicit false can be told from unset; both leave it off.
	Enabled *bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	// MaxRecords is how many records the session API keeps in memory, newest first. 0 means the
	// default, 10000. Older records leave the window, not the file.
	MaxRecords int `yaml:"max_records,omitempty" json:"max_records,omitempty"`
}

// AuditEnabled reports whether the audit store should run. Safe on a nil receiver.
func (c *SessionAuditConfig) AuditEnabled() bool {
	return c != nil && c.Enabled != nil && *c.Enabled
}

// Validate is called from the loader when session.audit is present.
func (c *SessionAuditConfig) Validate() error {
	if c.MaxRecords < 0 {
		return fmt.Errorf("session.audit.max_records must not be negative, got %d", c.MaxRecords)
	}
	return nil
}
