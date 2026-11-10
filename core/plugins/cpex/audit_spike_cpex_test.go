// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

//go:build cpex && cortexaudit

package cpex

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	rcpex "github.com/contextforge-org/cpex/go/cpex"
	"github.com/rossoctl/cortex/core/pipeline"
)

// captureStderr points fd 2 at a temp file until the returned func runs,
// so records the Rust sink writes to stderr can be read back.
func captureStderr(t *testing.T) (path string, restore func()) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "stderr.ndjson")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := syscall.Dup(2)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Dup2(int(f.Fd()), 2); err != nil {
		t.Fatal(err)
	}
	return path, func() {
		_ = syscall.Dup2(saved, 2)
		_ = syscall.Close(saved)
		_ = f.Close()
	}
}

func ocsfRecords(t *testing.T, path string) []map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []map[string]any
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		if rec["class_uid"] == float64(6003) {
			out = append(out, rec)
		}
	}
	return out
}

func writeSigningKey(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ocsf-signing.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func publicPEM(t *testing.T, keyPath string) []byte {
	t.Helper()
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(key.(*ecdsa.PrivateKey).Public())
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// The OCSF sink, registered through the cortex-audit FFI build, records
// every verdict the CPEX plugin gets: an allow and a deny each leave a
// chained, DSSE-signed OCSF API Activity record.
func TestSpikeOCSFSinkRecordsCPEXVerdicts(t *testing.T) {
	eng, err := rcpex.NewPolicyEngineDefault()
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.EnableAPL(); err != nil {
		t.Fatal(err)
	}
	if err := registerAuditFactories(eng); err != nil {
		t.Fatal(err)
	}
	mgr := &cpexManager{mgr: eng}

	keyPath := writeSigningKey(t)
	path, restore := captureStderr(t)
	p := enginePlugin(t, mgr, `
engine_settings:
  dispatch: policy
  audit_stream_namespace: cortex-spike
  capture_content_provenance: true
  content_provenance_key: unkeyed

plugins:
  - name: ocsf-audit
    kind: audit/ocsf
    mode: audit
    capabilities: [read_subject, read_roles, read_agent, read_labels]
    config:
      destination: stderr
      chain: true
      signing: dsse
      signing_key_pem_path: `+keyPath+`
      signing_key_id: cortex-spike-1
      authority_uid: cortex-spike

routes:
  - tool: get_compensation
    authorization:
      pre_invocation:
        - "require(role.hr)"
`)

	hr := toolCall("get_compensation", nil)
	hr.Identity = claimsIdentity{sub: "bob", scopes: []string{"hr"}}
	wantContinue(t, "hr", p.OnRequest(context.Background(), hr))

	eng2 := toolCall("get_compensation", nil)
	eng2.Identity = claimsIdentity{sub: "alice", scopes: []string{"engineer"}}
	if a := p.OnRequest(context.Background(), eng2); a.Violation == nil {
		t.Fatalf("engineer: action = %v, want reject", a.Type)
	}

	// The sink writes on blocking workers, so give it a moment.
	var recs []map[string]any
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if recs = ocsfRecords(t, path); len(recs) >= 2 {
			break
		}
	}
	restore()

	raw, _ := os.ReadFile(path)
	t.Logf("captured stderr:\n%s", raw)
	// SPIKE_OUT keeps the records and the public key for an offline check.
	if dir := os.Getenv("SPIKE_OUT"); dir != "" {
		_ = os.WriteFile(filepath.Join(dir, "records.ndjson"), raw, 0o600)
		_ = os.WriteFile(filepath.Join(dir, "ocsf-signing.pub.pem"), publicPEM(t, keyPath), 0o600)
	}
	if len(recs) < 2 {
		t.Fatalf("got %d OCSF records, want at least 2 (allow and deny)", len(recs))
	}
	var allowed, denied bool
	for _, r := range recs {
		switch r["action"] {
		case "Allowed":
			allowed = true
		case "Denied":
			denied = true
		}
		if att, _ := r["attestation_list"].([]any); len(att) == 0 {
			t.Errorf("record %v has no attestation", r["metadata"])
		}
	}
	if !allowed || !denied {
		t.Fatalf("allowed=%v denied=%v, want both", allowed, denied)
	}
}

// A keyed content digest loads through CPEX: its host wiring installs the
// env, file and vault secret providers, so content_provenance_key can name a
// secrets.values entry.
func TestSpikeKeyedContentProvenanceLoads(t *testing.T) {
	eng, err := rcpex.NewPolicyEngineDefault()
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.EnableAPL(); err != nil {
		t.Fatal(err)
	}
	if err := registerAuditFactories(eng); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "provenance.key"), []byte("0123456789abcdef0123456789abcdef"), 0o600); err != nil {
		t.Fatal(err)
	}

	path, restore := captureStderr(t)
	p := enginePlugin(t, &cpexManager{mgr: eng}, `
engine_settings:
  dispatch: policy
  audit_stream_namespace: cortex-spike
  capture_content_provenance: true
  content_provenance_key: provenance_key

secrets:
  providers:
    local: { kind: file, base_dir: `+dir+` }
  values:
    provenance_key: { provider: local, ref: provenance.key }

plugins:
  - name: ocsf-audit
    kind: audit/ocsf
    mode: audit
    config:
      destination: stderr
      chain: true

routes:
  - tool: get_compensation
    authorization:
      pre_invocation: ["allow"]
`)
	wantContinue(t, "call", p.OnRequest(context.Background(), toolCall("get_compensation", nil)))

	var recs []map[string]any
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if recs = ocsfRecords(t, path); len(recs) >= 1 {
			break
		}
	}
	restore()
	if len(recs) == 0 {
		raw, _ := os.ReadFile(path)
		t.Fatalf("no OCSF record; stderr:\n%s", raw)
	}
	content, _ := recs[0]["unmapped"].(map[string]any)["aid.content"].(map[string]any)
	t.Logf("aid.content = %v", content)
	// The same call's plain SHA-256 digest, from the unkeyed test above.
	const unkeyed = "sha256:04f46c2769ddd3a68fc02ec1f5bccbebbbf0656c123613eb3627aba3dabc9c41"
	if content["input_hash"] == unkeyed {
		t.Fatalf("input_hash is the plain SHA-256 digest; the key was not applied")
	}
}

// With the file exporter, records land in an append-only NDJSON file that
// Cortex owns, instead of the process's stderr.
func TestSpikeFileExporterWritesRecords(t *testing.T) {
	eng, err := rcpex.NewPolicyEngineDefault()
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.EnableAPL(); err != nil {
		t.Fatal(err)
	}
	if err := registerAuditFactories(eng); err != nil {
		t.Fatal(err)
	}
	keyPath := writeSigningKey(t)
	out := filepath.Join(t.TempDir(), "records.ndjson")

	p := enginePlugin(t, &cpexManager{mgr: eng}, `
engine_settings:
  dispatch: policy
  audit_stream_namespace: cortex-spike

plugins:
  - name: ocsf-audit
    kind: audit/ocsf
    mode: audit
    capabilities: [read_subject, read_roles]
    config:
      exporters:
        - { kind: file, path: `+out+`, fsync: batch }
      chain: true
      signing: dsse
      signing_key_pem_path: `+keyPath+`
      signing_key_id: cortex-spike-1
      authority_uid: cortex-spike

routes:
  - tool: get_compensation
    authorization:
      pre_invocation:
        - "require(role.hr)"
`)
	for _, who := range []claimsIdentity{
		{sub: "bob", scopes: []string{"hr"}},
		{sub: "alice", scopes: []string{"engineer"}},
		{sub: "bob", scopes: []string{"hr"}},
	} {
		call := toolCall("get_compensation", nil)
		call.Identity = who
		p.OnRequest(context.Background(), call)
	}

	var recs []map[string]any
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if recs = ocsfFileRecords(t, out); len(recs) >= 3 {
			break
		}
	}
	if len(recs) != 3 {
		t.Fatalf("got %d records in %s, want 3", len(recs), out)
	}
	if dir := os.Getenv("SPIKE_OUT"); dir != "" {
		raw, _ := os.ReadFile(out)
		_ = os.WriteFile(filepath.Join(dir, "file-export.ndjson"), raw, 0o600)
		_ = os.WriteFile(filepath.Join(dir, "file-export.pub.pem"), publicPEM(t, keyPath), 0o600)
	}
}

func ocsfFileRecords(t *testing.T, path string) []map[string]any {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		return nil
	}
	return ocsfRecords(t, path)
}

// A record names the request and session it belongs to: the request id is
// cortex's own (the id its session events carry), and with
// session_source: resolved the session is cortex's session too.
func TestSpikeRecordsJoinCortexRequestAndSession(t *testing.T) {
	mgr, err := NewManager(ManagerOptions{SessionSource: sessionSourceResolved})
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "records.ndjson")
	p := NewCPEX()
	p.newManager = func(ManagerOptions) (Manager, error) { return mgr, nil }
	raw, err := json.Marshal(map[string]any{
		"hooks":          map[string]any{"on_request": []string{HookToolPreInvoke}},
		"session_source": sessionSourceResolved,
		"config": `
engine_settings:
  dispatch: policy
  audit_stream_namespace: cortex-spike
plugins:
  - name: ocsf-audit
    kind: audit/ocsf
    mode: audit
    capabilities: [read_subject, read_agent]
    config:
      exporters:
        - { kind: file, path: ` + out + ` }
routes:
  - tool: get_weather
    authorization:
      pre_invocation: ["allow"]
`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Configure(raw); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	if err := p.Init(context.Background()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	t.Cleanup(func() { _ = p.Shutdown(context.Background()) })

	call := toolCall("get_weather", http.Header{"X-Request-Id": {"caller-chosen"}})
	call.Session = &pipeline.SessionView{ID: "claude-1"}
	call.SessionSource = pipeline.SessionSourceProcess
	wantContinue(t, "get_weather", p.OnRequest(context.Background(), call))

	var recs []map[string]any
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if recs = ocsfFileRecords(t, out); len(recs) >= 1 {
			break
		}
	}
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	unmapped, _ := recs[0]["unmapped"].(map[string]any)
	if got, want := unmapped["cmf.request.request_id"], call.RequestID(); got != want {
		t.Errorf("cmf.request.request_id = %v, want cortex's request id %q", got, want)
	}
	agent, _ := recs[0]["ai_agent"].(map[string]any)
	if got := agent["instance_uid"]; got != "claude-1" {
		t.Errorf("ai_agent.instance_uid = %v, want the cortex session claude-1", got)
	}
}
