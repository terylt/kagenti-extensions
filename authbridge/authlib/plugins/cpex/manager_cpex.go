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

// Initialize honors ctx's deadline. The rcpex binding's Initialize is
// blocking and NOT context-aware (no ctx param; see
// PluginManager.Initialize), so we run it in a goroutine and select on
// ctx.Done vs completion. On ctx cancellation we return ctx.Err() so
// the caller's init budget (main.go's 60s initCtx) is actually
// enforced.
//
// We deliberately do NOT call Shutdown on cancellation: rcpex's
// Shutdown takes the manager's write lock while Initialize holds the
// read lock, so Shutdown would block on (not abort) the in-flight
// cpex_initialize — it can't cancel it. The orphaned goroutine
// finishes on its own when cpex_initialize returns; its handle is
// reclaimed by the framework's later Shutdown (or the GC finalizer).
//
// TODO: switch to a context-aware Initialize if the rcpex bindings
// gain one, so a stuck init can be cancelled rather than merely
// abandoned.
func (c *cpexManager) Initialize(ctx context.Context) error {
	done := make(chan error, 1)
	go func() {
		done <- c.mgr.Initialize()
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
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
	// Phase is taken from the framework-set current phase, NOT inferred
	// from body length: an empty-bodied response (HTTP 204, empty tool
	// result) must still be treated as the response phase so response
	// policy fires. CurrentPhase is "" only outside a dispatch (defensive
	// — Invoke always runs inside OnRequest/OnResponse), which falls
	// through to the request phase.
	isResponse := pctx.CurrentPhase() == pipeline.InvocationPhaseResponse
	payload, ext := buildCMF(pctx, isResponse)

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
		if applyErr := applyModificationsToPctx(pctx, pres, isResponse); applyErr != nil {
			// A modification CPEX requested could not be applied — a
			// decode failure (CPEX/pctx contract mismatch) or a body
			// rewrite we have no re-serializer for. Either way the
			// modified message did NOT make it onto pctx, so forwarding
			// the original would silently drop the policy's intent
			// (e.g. a PII redaction). Surface it as DecisionError +
			// error so runHooks routes through fail_open: block when
			// fail_open=false, allow-with-log when true.
			slog.Warn("cpex: failed to apply modifications",
				"hook", hookName, "error", applyErr)
			return Result{Decision: DecisionError, Reason: applyErr.Error()},
				fmt.Errorf("cpex apply modifications %q: %w", hookName, applyErr)
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

// backgroundWaitTimeout bounds how long awaitBackground blocks on a
// single Invoke's background tasks. A stalled sink (e.g. an audit
// endpoint that never responds) would otherwise pin one goroutine per
// request indefinitely; the deadline caps the leak at one goroutine for
// at most this long. Best-effort — the result only feeds slog — so a
// generous value avoids dropping work product from merely-slow sinks.
const backgroundWaitTimeout = 30 * time.Second

// awaitBackground blocks on bg.Wait — which returns when every
// background sub-plugin spawned by this Invoke has finished — and
// logs the per-sub-plugin error report (if any) via slog. Operators
// pipe the slog output to their audit/observability stack.
//
// Bounded by backgroundWaitTimeout: bg.Wait runs in an inner goroutine
// and we select on it vs a timer. On timeout we log a WARN and return,
// so a stalled sink can't leak goroutines without bound. The inner
// goroutine still exits whenever bg.Wait eventually returns.
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
	type waitResult struct {
		errs []rcpex.PluginError
		err  error
	}
	done := make(chan waitResult, 1)
	go func() {
		errs, err := bg.Wait()
		done <- waitResult{errs: errs, err: err}
	}()

	timer := time.NewTimer(backgroundWaitTimeout)
	defer timer.Stop()

	select {
	case <-timer.C:
		slog.Warn("cpex: background tasks wait timed out",
			"hook", hook, "req_id", reqID,
			"elapsed", time.Since(start), "timeout", backgroundWaitTimeout)
		return
	case res := <-done:
		elapsed := time.Since(start)
		if res.err != nil {
			slog.Warn("cpex: background tasks wait failed",
				"hook", hook, "req_id", reqID, "elapsed", elapsed, "error", res.err)
			return
		}
		for _, e := range res.errs {
			slog.Warn("cpex: background sub-plugin error",
				"hook", hook, "req_id", reqID, "elapsed", elapsed,
				"plugin", e.PluginName, "code", e.Code, "message", e.Message)
		}
	}
}

// applyModificationsToPctx writes CPEX's modified Extensions and body
// back onto pctx. MCP body modifications are re-serialized; inference /
// A2A body rewriting is not yet implemented and fails closed (see
// applyBodyModFromCMF).
//
// Extension changes applied:
//
//   - HttpExtension.RequestHeaders → pctx.Headers
//     Set the headers CPEX listed; preserve any pctx headers CPEX
//     didn't model (multi-value, e.g. Set-Cookie).
//   - SecurityExtension.Labels → pctx.Extensions.Security.Labels
//     Merge-add (no duplicates). Existing labels stay; new ones
//     append. Operators reading session events see the union.
func applyModificationsToPctx(pctx *pipeline.Context, pres *rcpex.PipelineResult, isResponse bool) error {
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
			if err := applyBodyModFromCMF(pctx, &payload.Message, isResponse); err != nil {
				return fmt.Errorf("apply body mod: %w", err)
			}
		}
	}

	return nil
}

// applyBodyModFromCMF dispatches the body-rewriting logic per format
// detected from pctx.Extensions. isResponse chooses between request and
// response body.
//
// Fail-closed contract: CPEX requested a body modification (e.g. a PII
// redaction). MCP traffic is re-serialized. For inference / A2A traffic
// there is no re-serialization path yet, so we cannot apply the change.
// Returning an error rather than silently forwarding the ORIGINAL body
// makes the caller (Invoke) surface a DecisionError that fail_open
// governs — an unappliable redaction blocks (fail_open=false) instead of
// leaking the unredacted body downstream.
func applyBodyModFromCMF(pctx *pipeline.Context, msg *rcpex.Message, isResponse bool) error {
	switch {
	case pctx.Extensions.MCP != nil:
		return applyMCPBodyModFromCMF(pctx, msg, isResponse)
	default:
		// Inference / A2A body rewriting not yet implemented — needs
		// format-specific re-serialization helpers (OpenAI messages,
		// A2A fragments). Fail closed: a requested redaction we can't
		// apply must not be dropped silently.
		slog.Warn("cpex: body modification requested but unsupported for this format — failing closed",
			"has_inference", pctx.Extensions.Inference != nil,
			"has_a2a", pctx.Extensions.A2A != nil)
		return fmt.Errorf("body modification requested but not supported for non-MCP traffic")
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
// Phase is supplied by the caller from pctx.CurrentPhase(), NOT inferred
// from body length (an empty-bodied response must still take the response
// path), NOT pctx.Direction (a reverse-proxy pctx stays Direction=Inbound
// for both phases), and NOT mcp.Result (mcp-parser runs AFTER cpex on the
// response, so Result isn't populated yet when we apply).
func applyMCPBodyModFromCMF(pctx *pipeline.Context, msg *rcpex.Message, isResponse bool) error {
	method := pctx.Extensions.MCP.Method
	if !isResponse {
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
// pipeline.Context. The phase (request vs response) is supplied by the
// caller from pctx.CurrentPhase() rather than inferred here. Mapping:
//
//	role          = "user" request, "assistant" response
//	body          → single text content part when len > 0
//	identity      → SecurityExtension.Subject (id, roles from Scopes())
//	identity      → AgentExtension.AgentID from ClientID()
//	headers       → HttpExtension.RequestHeaders (Authorization and
//	                Cookie stripped — they don't belong in policy
//	                context and would leak through CPEX traces)
func buildCMF(pctx *pipeline.Context, isResponse bool) (rcpex.MessagePayload, *rcpex.Extensions) {
	// Phase drives both the CMF role and which structured part we emit.
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

// (flattenHeaders, isSensitive, and the secretHeader* tables live in
// the tag-free headers.go so they're testable under the default
// CGO_ENABLED=0 build.)

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
		// Extension changes (headers, labels) and MCP body changes have
		// already been applied to pctx by applyModificationsToPctx
		// before mapResult runs. Report modify so the Invocation
		// reflects that policy touched the message.
		res.Decision = DecisionModify
		switch {
		case len(p.ModifiedPayload) > 0 && len(p.ModifiedExtensions) > 0:
			res.Reason = "policy modified headers/labels and body"
		case len(p.ModifiedPayload) > 0:
			res.Reason = "policy modified body"
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
