package cpex

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kagenti/kagenti-extensions/authbridge/authlib/pipeline"
)

// --- applyMCPRequestBodyMod ---

func TestMCPRequestBodyMod_ToolsCallArgsReplaced(t *testing.T) {
	pctx := &pipeline.Context{
		Body: []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_compensation","arguments":{"employee_id":"E001","include_ssn":true}}}`),
	}
	newArgs := map[string]any{"employee_id": "E001"} // include_ssn redacted
	mutated, err := applyMCPRequestBodyMod(pctx, "tools/call", MCPRequestBodyMod{NewArguments: newArgs})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !mutated {
		t.Fatal("expected mutated=true")
	}
	var decoded map[string]any
	if err := json.Unmarshal(pctx.Body, &decoded); err != nil {
		t.Fatalf("re-decode: %v", err)
	}
	args := decoded["params"].(map[string]any)["arguments"].(map[string]any)
	if _, has := args["include_ssn"]; has {
		t.Fatalf("include_ssn should have been removed from args: %v", args)
	}
	if args["employee_id"] != "E001" {
		t.Fatalf("employee_id lost in rewrite: %v", args)
	}
}

func TestMCPRequestBodyMod_PromptsGetArgsReplaced(t *testing.T) {
	pctx := &pipeline.Context{
		Body: []byte(`{"jsonrpc":"2.0","id":1,"method":"prompts/get","params":{"name":"weather","arguments":{"city":"SF"}}}`),
	}
	newArgs := map[string]any{"city": "REDACTED"}
	mutated, err := applyMCPRequestBodyMod(pctx, "prompts/get", MCPRequestBodyMod{NewArguments: newArgs})
	if err != nil || !mutated {
		t.Fatalf("mutated=%v err=%v", mutated, err)
	}
	if !strings.Contains(string(pctx.Body), `"city":"REDACTED"`) {
		t.Fatalf("city not redacted in body: %s", pctx.Body)
	}
}

func TestMCPRequestBodyMod_ResourcesReadURIReplaced(t *testing.T) {
	pctx := &pipeline.Context{
		Body: []byte(`{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"file:///secret"}}`),
	}
	mutated, err := applyMCPRequestBodyMod(pctx, "resources/read", MCPRequestBodyMod{NewURI: "file:///public"})
	if err != nil || !mutated {
		t.Fatalf("mutated=%v err=%v", mutated, err)
	}
	if !strings.Contains(string(pctx.Body), `"uri":"file:///public"`) {
		t.Fatalf("uri not rewritten: %s", pctx.Body)
	}
}

func TestMCPRequestBodyMod_EmptyArgsNoOp(t *testing.T) {
	orig := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":{"a":1}}}`)
	pctx := &pipeline.Context{Body: append([]byte(nil), orig...)}
	mutated, err := applyMCPRequestBodyMod(pctx, "tools/call", MCPRequestBodyMod{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if mutated {
		t.Fatal("expected mutated=false on empty mod")
	}
	if string(pctx.Body) != string(orig) {
		t.Fatalf("body changed despite no-op: %s", pctx.Body)
	}
}

func TestMCPRequestBodyMod_UnsupportedMethodNoOp(t *testing.T) {
	pctx := &pipeline.Context{
		Body: []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`),
	}
	mutated, err := applyMCPRequestBodyMod(pctx, "initialize", MCPRequestBodyMod{NewArguments: map[string]any{"x": 1}})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if mutated {
		t.Fatal("expected mutated=false for unsupported method")
	}
}

func TestMCPRequestBodyMod_MalformedJSONError(t *testing.T) {
	pctx := &pipeline.Context{Body: []byte(`{not json`)}
	_, err := applyMCPRequestBodyMod(pctx, "tools/call", MCPRequestBodyMod{NewArguments: map[string]any{"a": 1}})
	if err == nil {
		t.Fatal("expected error on malformed JSON")
	}
}

func TestMCPRequestBodyMod_EmptyBodyNoOp(t *testing.T) {
	pctx := &pipeline.Context{}
	mutated, err := applyMCPRequestBodyMod(pctx, "tools/call", MCPRequestBodyMod{NewArguments: map[string]any{"a": 1}})
	if err != nil || mutated {
		t.Fatalf("mutated=%v err=%v on empty body", mutated, err)
	}
}

func TestMCPRequestBodyMod_NoParamsObjectNoOp(t *testing.T) {
	pctx := &pipeline.Context{
		Body: []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`),
	}
	mutated, err := applyMCPRequestBodyMod(pctx, "tools/call", MCPRequestBodyMod{NewArguments: map[string]any{"a": 1}})
	if err != nil || mutated {
		t.Fatalf("mutated=%v err=%v on body without params", mutated, err)
	}
}

// --- applyMCPResponseBodyMod ---

func TestMCPResponseBodyMod_TextBlockReplaced(t *testing.T) {
	pctx := &pipeline.Context{
		ResponseBody: []byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"original payload with ssn:123-45-6789"}]}}`),
	}
	newContent := map[string]any{
		"employee_id": "E001",
		"name":        "Jane Smith",
		// SSN removed
	}
	mutated, err := applyMCPResponseBodyMod(pctx, "tools/call", newContent)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !mutated {
		t.Fatal("expected mutated=true")
	}
	// The new text block is JSON-stringified newContent (a nested
	// JSON-in-JSON shape), so the inner quotes appear escaped.
	body := string(pctx.ResponseBody)
	if !strings.Contains(body, `\"employee_id\"`) || !strings.Contains(body, `\"Jane Smith\"`) {
		t.Fatalf("new content not present in response: %s", body)
	}
	if strings.Contains(body, "123-45-6789") {
		t.Fatalf("old SSN still present in rewritten response: %s", body)
	}
}

func TestMCPResponseBodyMod_StructuredContentUpdated(t *testing.T) {
	pctx := &pipeline.Context{
		ResponseBody: []byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"x"}],"structuredContent":{"ssn":"123"}}}`),
	}
	newContent := map[string]any{"name": "Jane"}
	if _, err := applyMCPResponseBodyMod(pctx, "tools/call", newContent); err != nil {
		t.Fatalf("err: %v", err)
	}
	var decoded map[string]any
	json.Unmarshal(pctx.ResponseBody, &decoded)
	result := decoded["result"].(map[string]any)
	sc := result["structuredContent"].(map[string]any)
	if sc["ssn"] != nil {
		t.Fatalf("structuredContent.ssn should be gone: %v", sc)
	}
	if sc["name"] != "Jane" {
		t.Fatalf("structuredContent.name not updated: %v", sc)
	}
}

func TestMCPResponseBodyMod_NoStructuredContentNotIntroduced(t *testing.T) {
	// When the original response didn't have structuredContent, don't
	// introduce it on rewrite — clients sniffing for the new shape
	// would be surprised.
	pctx := &pipeline.Context{
		ResponseBody: []byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"x"}]}}`),
	}
	if _, err := applyMCPResponseBodyMod(pctx, "tools/call", map[string]any{"name": "Jane"}); err != nil {
		t.Fatalf("err: %v", err)
	}
	if strings.Contains(string(pctx.ResponseBody), "structuredContent") {
		t.Fatalf("structuredContent introduced when original didn't have it: %s", pctx.ResponseBody)
	}
}

func TestMCPResponseBodyMod_NotToolsCallNoOp(t *testing.T) {
	pctx := &pipeline.Context{
		ResponseBody: []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`),
	}
	mutated, err := applyMCPResponseBodyMod(pctx, "tools/list", map[string]any{"x": 1})
	if err != nil || mutated {
		t.Fatalf("mutated=%v err=%v for non-tools/call method", mutated, err)
	}
}

func TestMCPResponseBodyMod_EmptyBodyNoOp(t *testing.T) {
	pctx := &pipeline.Context{}
	mutated, err := applyMCPResponseBodyMod(pctx, "tools/call", map[string]any{"x": 1})
	if err != nil || mutated {
		t.Fatalf("mutated=%v err=%v on empty body", mutated, err)
	}
}

func TestMCPResponseBodyMod_NilContentNoOp(t *testing.T) {
	pctx := &pipeline.Context{
		ResponseBody: []byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"x"}]}}`),
	}
	mutated, err := applyMCPResponseBodyMod(pctx, "tools/call", nil)
	if err != nil || mutated {
		t.Fatalf("mutated=%v err=%v on nil newContent", mutated, err)
	}
}

func TestMCPResponseBodyMod_NoTextBlockNoMutation(t *testing.T) {
	// Response had only image/audio blocks; no text block to replace
	// and no structuredContent to update → no rewrite.
	pctx := &pipeline.Context{
		ResponseBody: []byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"image","data":"abc"}]}}`),
	}
	mutated, err := applyMCPResponseBodyMod(pctx, "tools/call", map[string]any{"x": 1})
	if err != nil || mutated {
		t.Fatalf("mutated=%v err=%v when no text block to replace", mutated, err)
	}
}

// --- stringifyForTextBlock ---

func TestStringifyForTextBlock(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{"plain text", "plain text"},
		{map[string]any{"k": "v"}, "{\n  \"k\": \"v\"\n}"},
		{[]int{1, 2}, "[\n  1,\n  2\n]"},
	}
	for _, tc := range cases {
		got := stringifyForTextBlock(tc.in)
		if got != tc.want {
			t.Errorf("stringifyForTextBlock(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
