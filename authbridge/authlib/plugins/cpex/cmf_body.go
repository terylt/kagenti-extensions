package cpex

import (
	"encoding/json"
	"fmt"

	"github.com/kagenti/kagenti-extensions/authbridge/authlib/pipeline"
)

// MCPRequestBodyMod describes what changes to apply to an MCP JSON-RPC
// request body. The cgo adapter extracts these values from a CPEX-
// modified CMF Message and hands them to applyMCPRequestBodyMod.
//
// Exactly one field is consumed per method:
//
//	tools/call     → NewArguments  → params.arguments
//	prompts/get    → NewArguments  → params.arguments
//	resources/read → NewURI        → params.uri
//
// Other methods are no-ops — the operator's APL policy can't rewrite
// protocol mechanics (initialize, tools/list, etc.) because there's
// no semantically meaningful target for the rewrite.
type MCPRequestBodyMod struct {
	NewArguments map[string]any
	NewURI       string
}

// applyMCPRequestBodyMod rewrites pctx.Body, which is expected to be
// an MCP JSON-RPC request. Returns mutated=true when the body was
// changed and SetBody was called; returns mutated=false (with no
// error) when the original body didn't match the expected shape
// (e.g., parsed JSON has no `params` object, method is unsupported,
// or the mod struct's relevant field is empty for the method).
//
// Mirrors praxis-cpex's reserialize_json_rpc_body so AuthBridge and
// praxis stay schema-compatible on the same CPEX policy YAML.
func applyMCPRequestBodyMod(pctx *pipeline.Context, method string, mod MCPRequestBodyMod) (mutated bool, err error) {
	if len(pctx.Body) == 0 {
		return false, nil
	}
	var envelope map[string]any
	if err := json.Unmarshal(pctx.Body, &envelope); err != nil {
		return false, fmt.Errorf("decode request body as JSON: %w", err)
	}
	params, _ := envelope["params"].(map[string]any)
	if params == nil {
		return false, nil
	}

	switch method {
	case "tools/call", "prompts/get":
		if len(mod.NewArguments) == 0 {
			return false, nil
		}
		params["arguments"] = mod.NewArguments
	case "resources/read":
		if mod.NewURI == "" {
			return false, nil
		}
		params["uri"] = mod.NewURI
	default:
		return false, nil
	}

	newBody, err := json.Marshal(envelope)
	if err != nil {
		return false, fmt.Errorf("re-serialize request body: %w", err)
	}
	pctx.SetBody(newBody)
	return true, nil
}

// applyMCPResponseBodyMod rewrites pctx.ResponseBody for a tools/call
// JSON-RPC response. The new content replaces:
//
//   - result.content[].text — the canonical MCP text block, stringified
//     as JSON (pretty-printed when possible).
//   - result.structuredContent — only when the original response had it.
//     Don't introduce structuredContent on a response that didn't carry
//     it; clients sniffing for the new shape would be surprised.
//
// Returns mutated=true when SetResponseBody was called; mutated=false
// when the body wasn't a tools/call response, had no result.content,
// or the response had no replaceable text block.
//
// Mirrors praxis-cpex's reserialize_json_rpc_response_body. Both
// gateways serialize newContent the same way so cross-gateway
// comparisons of identical policies produce identical bytes on the
// wire.
func applyMCPResponseBodyMod(pctx *pipeline.Context, method string, newContent any) (mutated bool, err error) {
	if method != "tools/call" {
		return false, nil
	}
	if len(pctx.ResponseBody) == 0 || newContent == nil {
		return false, nil
	}
	var envelope map[string]any
	if err := json.Unmarshal(pctx.ResponseBody, &envelope); err != nil {
		return false, fmt.Errorf("decode response body as JSON: %w", err)
	}
	result, ok := envelope["result"].(map[string]any)
	if !ok {
		return false, nil
	}

	replaced := false

	// Primary path: rewrite the first text block in result.content[].
	// This is what every MCP client we see today reads from.
	if contentArr, ok := result["content"].([]any); ok {
		for _, block := range contentArr {
			blockObj, ok := block.(map[string]any)
			if !ok {
				continue
			}
			if t, ok := blockObj["type"].(string); ok && t == "text" {
				blockObj["text"] = stringifyForTextBlock(newContent)
				replaced = true
				break
			}
		}
	}

	// Secondary path: update structuredContent when it was already
	// present. Operators can opt clients into the newer
	// structuredContent shape by populating it in the upstream
	// response; CPEX rewrites it consistently. We never introduce
	// it on a response that lacked it.
	if _, has := result["structuredContent"]; has {
		result["structuredContent"] = newContent
		replaced = true
	}

	if !replaced {
		return false, nil
	}

	newBody, err := json.Marshal(envelope)
	if err != nil {
		return false, fmt.Errorf("re-serialize response body: %w", err)
	}
	pctx.SetResponseBody(newBody)
	return true, nil
}

// stringifyForTextBlock turns the modified content value back into the
// string the MCP text block expects. We try pretty-printed JSON first
// (matches the upstream MCP server's typical output, makes diffs
// readable in session events); fall back to compact JSON on error;
// fall back to %v on impossible-to-marshal types.
func stringifyForTextBlock(v any) string {
	if s, ok := v.(string); ok {
		// Common case: the redactor handed back a string verbatim.
		return s
	}
	if b, err := json.MarshalIndent(v, "", "  "); err == nil {
		return string(b)
	}
	if b, err := json.Marshal(v); err == nil {
		return string(b)
	}
	return fmt.Sprintf("%v", v)
}
