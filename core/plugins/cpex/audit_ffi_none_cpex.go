// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

//go:build cpex && !cortexaudit

package cpex

import rcpex "github.com/contextforge-org/cpex/go/cpex"

// registerAuditFactories registers nothing: the released libcpex_ffi.a has
// no audit sink to register. A policy naming `kind: audit/ocsf` then fails
// to load with an unknown-kind error rather than running without its audit
// trail.
func registerAuditFactories(*rcpex.PolicyEngine) error { return nil }
