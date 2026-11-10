// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

//go:build cpex && cortexaudit

package cpex

/*
int cortex_audit_register_factories(void* engine);
*/
import "C"

import (
	"fmt"
	"unsafe"

	rcpex "github.com/contextforge-org/cpex/go/cpex"
)

// registerAuditFactories registers the OCSF audit sink (`audit/ocsf`) on
// eng, so a policy can name it with `kind: audit/ocsf`. It needs the
// cortex-audit build of libcpex_ffi.a, which carries the sink beside CPEX's
// own FFI surface; the released library does not, which is why this file is
// behind the cortexaudit tag. Must run before LoadConfig.
func registerAuditFactories(eng *rcpex.PolicyEngine) error {
	return eng.RegisterFactories(func(handle unsafe.Pointer) error {
		if rc := C.cortex_audit_register_factories(handle); rc != 0 {
			return fmt.Errorf("cortex_audit_register_factories returned %d", rc)
		}
		return nil
	})
}
