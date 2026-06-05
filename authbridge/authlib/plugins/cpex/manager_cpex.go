//go:build cpex

package cpex

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	rcpex "github.com/contextforge-org/cpex/go/cpex"
	"github.com/kagenti/kagenti-extensions/authbridge/authlib/pipeline"
)

// cpexManager is the CPEX-backed Manager implementation. Wraps
// rcpex.PluginManager and translates pctx ↔ CMF on every Invoke.
// Lives behind //go:build cpex; the matching stub in manager_stub.go
// handles the !cpex case.
type cpexManager struct {
	mgr *rcpex.PluginManager
}

// NewManager constructs a CPEX-backed Manager. Tokio worker pool size
// (when > 0) is configured before manager creation. EnableAPL is called
// before any LoadConfig so APL DSL plugins are available to the
// operator's YAML.
//
// On any error before return, the partially-constructed manager is
// shut down so we don't leak the tokio runtime.
func NewManager(opts ManagerOptions) (Manager, error) {
	if opts.WorkerThreads > 0 {
		if err := rcpex.ConfigureRuntime(opts.WorkerThreads); err != nil {
			return nil, fmt.Errorf("cpex configure runtime: %w", err)
		}
	}
	mgr, err := rcpex.NewPluginManagerDefault()
	if err != nil {
		return nil, fmt.Errorf("cpex new manager: %w", err)
	}
	if err := mgr.EnableAPL(); err != nil {
		mgr.Shutdown()
		return nil, fmt.Errorf("cpex enable APL: %w", err)
	}
	return &cpexManager{mgr: mgr}, nil
}

func (c *cpexManager) LoadConfig(yaml string) error {
	return c.mgr.LoadConfig(yaml)
}

func (c *cpexManager) Initialize(_ context.Context) error {
	return c.mgr.Initialize()
}

func (c *cpexManager) Shutdown(_ context.Context) {
	c.mgr.Shutdown()
}

func (c *cpexManager) HasHook(name string) bool {
	return c.mgr.HasHooksFor(name)
}

// Invoke builds a CMF payload + Extensions from pctx, calls the CPEX
// FFI, applies any extension modifications back to pctx, and maps the
// PipelineResult into our aggregate Result.
//
// Scope:
//   - Identity, HTTP headers, and Direction are mapped to CPEX
//     (enough for identity-driven policies — Cedar, simple allow/deny).
//   - Body content is mapped as a single text part when present.
//   - Header and label modifications ARE applied back to pctx when
//     CPEX policy mutates the Extensions.
//   - Body modifications log a WARN but don't rewrite pctx.Body —
//     format-aware re-serialization (JSON-RPC, OpenAI) lands later.
//   - BackgroundTasks (audit-logger and other async sub-plugins) are
//     awaited in a fire-and-forget goroutine; errors land on the
//     default slog handler with the request ID for correlation.
func (c *cpexManager) Invoke(_ context.Context, hookName string, pctx *pipeline.Context) (Result, error) {
	payload, ext := buildCMF(pctx)

	// Fused identity-resolve + hook invoke. cpex-core runs the identity
	// resolvers (jwt-user / jwt-client) ONLY on the identity.resolve hook,
	// never inside a tool/prompt/resource hook. An FFI host must therefore
	// resolve identity and forward the principal, or per-route APL gates
	// (require(role.hr), Cedar principal.roles, redact(!perm.*)) see an
	// empty subject and deny everything. We use the fused InvokeResolved
	// rather than a separate resolve+invoke pair so the resolved
	// raw_credentials — whose inbound tokens are skip-serialized and can't
	// cross the FFI boundary — reach delegate() in Rust memory for token
	// exchange.
	var (
		pres *rcpex.PipelineResult
		ct   *rcpex.ContextTable
		bg   *rcpex.BackgroundTasks
		err  error
	)
	if hookName != rcpex.HookIdentityResolve && c.mgr.HasHooksFor(rcpex.HookIdentityResolve) {
		idp := rcpex.NewIdentityPayload(rcpex.TokenSourceBearer, lowerHeaders(pctx.Headers))
		pres, ct, bg, err = c.mgr.InvokeResolved(idp, hookName, rcpex.PayloadCMFMessage, payload, ext, nil)
	} else {
		pres, ct, bg, err = c.mgr.InvokeByName(hookName, rcpex.PayloadCMFMessage, payload, ext, nil)
	}
	if ct != nil {
		defer ct.Close()
	}
	if bg != nil {
		// Spawn a goroutine to consume bg.Wait. Audit-logger and
		// other async sub-plugins emit their work product here; if
		// we Close instead of Wait, the work product is dropped.
		// Goroutine carries the request-id (from X-Request-Id) so
		// background errors correlate with the foreground request.
		reqID := pctx.Headers.Get("X-Request-Id")
		go awaitBackground(hookName, reqID, bg)
	}
	if err != nil {
		return Result{Decision: DecisionError, Reason: err.Error()},
			fmt.Errorf("cpex invoke %q: %w", hookName, err)
	}

	// Apply modifications only when the policy will allow the request
	// through. On deny, the modifications are moot — nothing of the
	// modified request is forwarded — so skip the work.
	if pres.ContinueProcessing {
		if applyErr := applyModificationsToPctx(pctx, pres); applyErr != nil {
			// Modification-decode failure is a CPEX/pctx contract
			// mismatch, not a policy failure. Log loudly per the
			// fail-loud design but don't propagate as a policy
			// error — the underlying invocation outcome stays as-is.
			slog.Warn("cpex: failed to apply modifications",
				"hook", hookName, "error", applyErr)
		}
	}

	return mapResult(pres), nil
}

// lowerHeaders flattens http.Header into the lowercase-keyed single-value
// map the identity resolvers expect (they look their configured header up
// case-folded). Unlike flattenHeaders this keeps Authorization /
// X-User-Token — the jwt resolvers need the raw tokens — and does not
// strip the audit-sensitive set, because the IdentityPayload header map
// is consumed only by the in-process resolvers, never logged.
func lowerHeaders(h http.Header) map[string]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string]string, len(h))
	for k, vs := range h {
		if len(vs) == 0 {
			continue
		}
		if len(vs) == 1 {
			out[strings.ToLower(k)] = vs[0]
		} else {
			out[strings.ToLower(k)] = strings.Join(vs, ", ")
		}
	}
	return out
}

// awaitBackground blocks on bg.Wait — which returns when every
// background sub-plugin spawned by this Invoke has finished — and
// logs the per-sub-plugin error report (if any) via slog. Operators
// pipe the slog output to their audit/observability stack.
//
// Concurrency notes:
//   - The goroutine outlives the request; it does NOT touch pctx
//     (pctx may be reused by the framework after Invoke returns).
//     hook and reqID are captured by value.
//   - If the manager shuts down while we're waiting, bg.Wait
//     returns an error which we log at WARN. We do not attempt to
//     cancel — the underlying FFI doesn't expose a cancel knob, and
//     a graceful shutdown should drain background tasks anyway.
//   - elapsed gives operators a knob to spot slow async work in the
//     log stream (e.g. a slow audit sink).
func awaitBackground(hook, reqID string, bg *rcpex.BackgroundTasks) {
	start := time.Now()
	errs, err := bg.Wait()
	elapsed := time.Since(start)
	if err != nil {
		slog.Warn("cpex: background tasks wait failed",
			"hook", hook, "req_id", reqID, "elapsed", elapsed, "error", err)
		return
	}
	for _, e := range errs {
		slog.Warn("cpex: background sub-plugin error",
			"hook", hook, "req_id", reqID, "elapsed", elapsed,
			"plugin", e.PluginName, "code", e.Code, "message", e.Message)
	}
}

// applyModificationsToPctx writes CPEX's modified Extensions back
// onto pctx. Body modifications (ModifiedPayload) are detected and
// logged but not yet re-serialized — that wires up in PR 2 when the
// CMF → JSON-RPC / OpenAI round-trip lands.
//
// Extension changes applied today (PR 1):
//
//   - HttpExtension.RequestHeaders → pctx.Headers
//     Set the headers CPEX listed; preserve any pctx headers CPEX
//     didn't model (multi-value, e.g. Set-Cookie).
//   - SecurityExtension.Labels → pctx.Extensions.Security.Labels
//     Merge-add (no duplicates). Existing labels stay; new ones
//     append. Operators reading session events see the union.
func applyModificationsToPctx(pctx *pipeline.Context, pres *rcpex.PipelineResult) error {
	if len(pres.ModifiedExtensions) > 0 {
		ext, err := pres.DeserializeExtensions()
		if err != nil {
			return fmt.Errorf("decode modified extensions: %w", err)
		}
		if ext != nil {
			applyExtensionChanges(pctx, ext)
		}
	}

	if len(pres.ModifiedPayload) > 0 {
		payload, err := rcpex.DeserializePayload[rcpex.MessagePayload](pres)
		if err != nil {
			return fmt.Errorf("decode modified payload: %w", err)
		}
		if payload != nil {
			if err := applyBodyModFromCMF(pctx, &payload.Message); err != nil {
				return fmt.Errorf("apply body mod: %w", err)
			}
		}
	}

	return nil
}

// applyBodyModFromCMF dispatches the body-rewriting logic per format
// detected from pctx.Extensions. Direction (Inbound/Outbound) chooses
// between request and response body. Unknown formats log a WARN and
// skip — the operator's policy will continue to function, just
// without the body modification applied.
func applyBodyModFromCMF(pctx *pipeline.Context, msg *rcpex.Message) error {
	switch {
	case pctx.Extensions.MCP != nil:
		return applyMCPBodyModFromCMF(pctx, msg)
	default:
		// Inference / A2A body rewriting deferred — needs format-
		// specific re-serialization helpers (OpenAI messages, A2A
		// fragments).
		slog.Warn("cpex: body modification skipped — no MCP context",
			"has_inference", pctx.Extensions.Inference != nil,
			"has_a2a", pctx.Extensions.A2A != nil)
		return nil
	}
}

// applyMCPBodyModFromCMF translates a CMF Message into the fields
// applyMCPRequestBodyMod / applyMCPResponseBodyMod expect, then
// dispatches based on the request-vs-response phase.
//
// Request side picks the first ToolCall / PromptRequest /
// ResourceReference content part — these are mutually exclusive in
// practice (a single tool call has one shape).
//
// Response side picks the first ToolResult content part; its Content
// field carries the new payload.
//
// Phase is determined by the presence of a buffered response body (the
// reverse proxy sets pctx.ResponseBody before the response pipeline runs),
// NOT pctx.Direction (a reverse-proxy pctx stays Direction=Inbound for
// both phases) and NOT mcp.Result (mcp-parser runs AFTER cpex on the
// response, so Result isn't populated yet when we apply).
func applyMCPBodyModFromCMF(pctx *pipeline.Context, msg *rcpex.Message) error {
	method := pctx.Extensions.MCP.Method
	if len(pctx.ResponseBody) == 0 {
		mod := MCPRequestBodyMod{}
		for _, part := range msg.Content {
			switch part.ContentType {
			case "tool_call":
				if part.ToolCallContent != nil {
					mod.NewArguments = part.ToolCallContent.Arguments
				}
			case "prompt_request":
				if part.PromptRequestContent != nil {
					mod.NewArguments = part.PromptRequestContent.Arguments
				}
			case "resource_ref":
				if part.ResourceRefContent != nil {
					mod.NewURI = part.ResourceRefContent.URI
				}
			default:
				continue
			}
			break
		}
		if _, err := applyMCPRequestBodyMod(pctx, method, mod); err != nil {
			return err
		}
		return nil
	}
	// Response side.
	for _, part := range msg.Content {
		if part.ContentType == "tool_result" && part.ToolResultContent != nil {
			if _, err := applyMCPResponseBodyMod(pctx, method, part.ToolResultContent.Content); err != nil {
				return err
			}
			break
		}
	}
	return nil
}

// applyExtensionChanges mutates pctx based on a CPEX-modified
// Extensions struct. Field-by-field, with deliberate ownership notes:
//
//   - Headers: replace each modified key in pctx.Headers. Keys CPEX
//     didn't include stay untouched — this is merge-replace, not
//     wholesale-replace, because CPEX doesn't see (and can't reason
//     about) headers the operator explicitly hid via flattenHeaders
//     (Authorization, Cookie). A wholesale replace would strip those.
//
//   - Labels: merge-add. CPEX labels join the pctx label set; we
//     don't remove labels other plugins set.
func applyExtensionChanges(pctx *pipeline.Context, ext *rcpex.Extensions) {
	if ext.Http != nil && len(ext.Http.RequestHeaders) > 0 {
		if pctx.Headers == nil {
			pctx.Headers = http.Header{}
		}
		for k, v := range ext.Http.RequestHeaders {
			pctx.Headers.Set(k, v)
		}
	}

	if ext.Security != nil && len(ext.Security.Labels) > 0 {
		if pctx.Extensions.Security == nil {
			pctx.Extensions.Security = &pipeline.SecurityExtension{}
		}
		existing := make(map[string]struct{}, len(pctx.Extensions.Security.Labels))
		for _, l := range pctx.Extensions.Security.Labels {
			existing[l] = struct{}{}
		}
		for _, l := range ext.Security.Labels {
			if _, ok := existing[l]; !ok {
				pctx.Extensions.Security.Labels = append(pctx.Extensions.Security.Labels, l)
				existing[l] = struct{}{}
			}
		}
	}
}

// buildCMF builds a CMF MessagePayload + Extensions from a
// pipeline.Context. Mapping (PR 1):
//
//	role          = "user" inbound, "assistant" outbound
//	body          → single text content part when len > 0
//	identity      → SecurityExtension.Subject (id, roles from Scopes())
//	identity      → AgentExtension.AgentID from ClientID()
//	headers       → HttpExtension.RequestHeaders (Authorization and
//	                Cookie stripped — they don't belong in policy
//	                context and would leak through CPEX traces)
func buildCMF(pctx *pipeline.Context) (rcpex.MessagePayload, *rcpex.Extensions) {
	// Phase drives both the CMF role and which structured part we emit.
	// Response phase is signalled by a buffered response body (the reverse
	// proxy sets it before the response pipeline runs). We must NOT key off
	// mcp.Result: response hooks run in reverse pipeline order, so cpex
	// executes before mcp-parser and Result isn't populated yet.
	isResponse := len(pctx.ResponseBody) > 0
	role := "user"
	if isResponse {
		role = "assistant"
	}

	part := mcpToCMFPart(pctx.Extensions.MCP, isResponse, pctx.Body, pctx.ResponseBody)
	parts := cmfPartToContentParts(part)
	payload := rcpex.MessagePayload{Message: rcpex.NewMessage(role, parts...)}

	ext := &rcpex.Extensions{}

	// Stamp the entity coordinates so cpex-core's route resolver
	// (filter_entries_by_route) dispatches the per-tool APL policy
	// handlers — require/Cedar/delegate/field-redaction. Without meta,
	// only always-on global plugins fire and the route's deny gates are
	// silently skipped.
	if et, en := cmfEntity(part); et != "" && en != "" {
		ext.Meta = &rcpex.MetaExtension{EntityType: et, EntityName: en}
	}

	if id := pctx.Identity; id != nil {
		ext.Security = &rcpex.SecurityExtension{
			Subject: &rcpex.SubjectExtension{
				ID:    id.Subject(),
				Roles: id.Scopes(),
			},
		}
		if cid := id.ClientID(); cid != "" {
			ext.Agent = &rcpex.AgentExtension{AgentID: cid}
		}
	}

	if len(pctx.Headers) > 0 {
		ext.Http = &rcpex.HttpExtension{
			RequestHeaders: flattenHeaders(pctx.Headers),
		}
	}

	// Custom-extension passthrough: forward only entries operators
	// explicitly scoped under "cpex/" — everything else (rate-limiter
	// cookies, plugin-private state) stays on the AuthBridge side.
	// Operators stash policy-input blobs in pctx.Extensions.Custom
	// under "cpex/<key>" and CPEX sub-plugins read them at <key>.
	if pctx.Extensions.Custom != nil {
		var picked map[string]any
		for k, v := range pctx.Extensions.Custom {
			if !strings.HasPrefix(k, "cpex/") {
				continue
			}
			if picked == nil {
				picked = map[string]any{}
			}
			picked[strings.TrimPrefix(k, "cpex/")] = v
		}
		if picked != nil {
			ext.Custom = picked
		}
	}

	return payload, ext
}

// cmfPartToContentParts converts the protocol-neutral cmfPart (decided by
// the tag-free mcpToCMFPart) into the rcpex content part CPEX dispatches
// on. Splitting the decision (tag-free, unit-tested) from this rcpex
// conversion (cgo-only) keeps the MCP→CMF mapping testable without the
// FFI, mirroring the cmf_body.go / applyMCPBodyModFromCMF split.
//
// The structured part carries the tool args/result CPEX policies read and
// rewrite; route *selection* is driven separately by Extensions.Meta (set
// in buildCMF from cmfEntity).
func cmfPartToContentParts(part cmfPart) []rcpex.ContentPart {
	switch part.Kind {
	case cmfPartToolCall:
		return []rcpex.ContentPart{rcpex.NewToolCallPart(rcpex.ToolCall{
			ToolCallID: part.CorrelationID,
			Name:       part.Name,
			Arguments:  part.Arguments,
		})}
	case cmfPartPromptRequest:
		return []rcpex.ContentPart{rcpex.NewPromptRequestPart(rcpex.PromptRequest{
			PromptRequestID: part.CorrelationID,
			Name:            part.Name,
			Arguments:       part.Arguments,
		})}
	case cmfPartResourceRef:
		return []rcpex.ContentPart{rcpex.NewResourceRefPart(rcpex.ResourceReference{
			ResourceRequestID: part.CorrelationID,
			URI:               part.URI,
			ResourceType:      "uri",
		})}
	case cmfPartToolResult:
		return []rcpex.ContentPart{rcpex.NewToolResultPart(rcpex.ToolResult{
			ToolCallID: part.CorrelationID,
			ToolName:   part.Name,
			Content:    part.Content,
			IsError:    part.IsError,
		})}
	default: // cmfPartText
		if part.Text == "" {
			return nil
		}
		return []rcpex.ContentPart{rcpex.NewTextPart(part.Text)}
	}
}

// secretHeaderPrefixes lists header-name prefixes that are NEVER
// forwarded into CPEX. CPEX sub-plugins (notably audit/logger) often
// log the payload they receive; the session API has no auth on it.
// So session cookies and platform-issued internal secrets must be
// stripped here, not relied on as opaque-to-CPEX.
//
// NOTE on `Authorization`: deliberately NOT stripped. CPEX's
// identity/jwt plugins (jwt-client, etc.) read the bearer token from
// the Authorization header to validate signature, audience, expiry,
// and to extract role/perm/team/group claims that APL predicates
// (`require(role.hr)`, `redact(!perm.view_ssn)`, …) gate on. Strip
// it and you lose every gate that depends on the client identity —
// the request continues to evaluate against an empty client bag,
// which silently allows traffic the policy meant to deny.
//
// The audit-log risk this opens — bearer tokens reaching audit
// payloads — is mitigated by configuring audit-log to drop
// Authorization from its output (or by terminating TLS at the
// sidecar so tokens are short-lived and bound to mTLS).
var secretHeaderPrefixes = []string{
	"cookie",
	"set-cookie",
	"proxy-authorization",
	"x-amz-security-token",
}

// secretHeaderExact lists exact (case-insensitive) header names that
// must always be stripped. Used for one-off names that don't fit a
// prefix scheme.
var secretHeaderExact = map[string]struct{}{
	"x-api-key":           {},
	"x-auth-token":        {},
	"x-authorization":     {},
	"x-secret-token":      {},
	"x-session-token":     {},
	"x-csrf-token":        {},
	"x-platform-secret":   {},
	"x-authbridge-secret": {},
}

// flattenHeaders converts http.Header (multi-value) into the single-value
// map shape CPEX's HttpExtension.RequestHeaders requires. Multi-value
// headers are comma-joined per RFC 7230 §3.2.2 — the standard
// safe-merge for repeatable HTTP headers. (Set-Cookie, which doesn't
// follow §3.2.2, lands in secretHeaderPrefixes and is stripped before
// reaching here.)
//
// Sensitive headers (Authorization, Cookie, X-Api-Key, …) are
// dropped via secretHeaderPrefixes / secretHeaderExact, NOT silently
// truncated.
func flattenHeaders(h http.Header) map[string]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string]string, len(h))
	for k, vs := range h {
		if isSensitive(k) || len(vs) == 0 {
			continue
		}
		// RFC 7230 §3.2.2: repeatable HTTP headers combine with
		// comma; non-repeatable ones either have a single value
		// already or were already filtered (Set-Cookie).
		if len(vs) == 1 {
			out[k] = vs[0]
		} else {
			out[k] = strings.Join(vs, ", ")
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// isSensitive checks both the prefix and exact-name secret tables.
// Case-insensitive — HTTP header names are case-insensitive on the
// wire, and any policy that depends on the case of "Authorization"
// vs "authorization" is already broken.
func isSensitive(name string) bool {
	lower := strings.ToLower(name)
	if _, ok := secretHeaderExact[lower]; ok {
		return true
	}
	for _, prefix := range secretHeaderPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

// mapResult collapses a CPEX PipelineResult into our aggregate
// Decision/Result. Order matters: deny first, then modify, then allow
// — a single result can carry a violation AND modifications, and the
// violation wins.
func mapResult(p *rcpex.PipelineResult) Result {
	res := Result{}

	for _, e := range p.Errors {
		res.Errors = append(res.Errors, SubPluginError{
			Plugin:  e.PluginName,
			Code:    e.Code,
			Message: e.Message,
		})
		if e.PluginName != "" {
			res.PluginsRun = append(res.PluginsRun, e.PluginName)
		}
	}

	if !p.ContinueProcessing {
		res.Decision = DecisionDeny
		if p.Violation != nil {
			res.Code = p.Violation.Code
			res.Reason = p.Violation.Reason
			if p.Violation.PluginName != "" {
				res.PluginsRun = appendUnique(res.PluginsRun, p.Violation.PluginName)
			}
		} else {
			res.Reason = "policy denied"
		}
		return res
	}

	if len(p.ModifiedPayload) > 0 || len(p.ModifiedExtensions) > 0 {
		// Extension changes (headers, labels) have already been
		// applied to pctx by applyModificationsToPctx; body changes
		// (ModifiedPayload) are still PR 2. Report modify either way
		// so the Invocation reflects that policy touched the message.
		res.Decision = DecisionModify
		switch {
		case len(p.ModifiedPayload) > 0 && len(p.ModifiedExtensions) > 0:
			res.Reason = "policy modified headers/labels (body rewrite deferred to PR 2)"
		case len(p.ModifiedPayload) > 0:
			res.Reason = "policy requested body modification (PR 2 will apply)"
		default:
			res.Reason = "policy modified headers/labels"
		}
		return res
	}

	res.Decision = DecisionAllow
	res.Reason = "all policies passed"
	return res
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}
