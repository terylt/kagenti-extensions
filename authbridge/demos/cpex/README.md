# CPEX integration demos

Three layered configurations that exercise the `cpex` plugin against
the cpex-praxis demo's Keycloak + MCP backend. Each demo isolates one
authorization shape so operators can read the YAML and see exactly
what each layer adds.

| File | Adds | Demonstrates |
|---|---|---|
| `chain-cedar-gate.yaml` | Cedar PDP | Principal × resource decisions (engineering ↔ internal repos) |
| `chain-pii-scanner.yaml` | Validator/PII scanner | Body-content guardrails (deny on PII; APL `redact()` redacts) |
| `chain-combined.yaml`   | Both + audit logger | Realistic stack: APL coarse gate → Cedar → PII → audit |

Each YAML is a complete AuthBridge config that the `authbridge-cpex`
binary accepts via `--config`. Sub-plugins on the CPEX side
(`pdp/cedar-direct`, `validator/pii-scan`, `audit/logger`) are
shipped in the bundled APL distribution at the pinned
`CPEX_FFI_VERSION`.

## Backend dependencies

These demos consume the same backends as the cpex-praxis demo at
`integrations/praxis-cpex/examples/demo/` in the cpex repository:

- **Keycloak**: realm `cpex-demo`, users `alice` (engineer), `bob`
  (HR with view_ssn), `eve` (HR without view_ssn). Imports from
  `praxis-cpex/examples/demo/keycloak/realm-export.json`.
- **MCP backend** (`hr-mcp:9100`): FastAPI server speaking JSON-RPC
  with the `get_compensation` and `search_repos` tools.

Bring them up via the praxis demo's `docker-compose.yml` (or
equivalent) before launching AuthBridge.

## Running

```bash
# 1. Build the authbridge-cpex binary against a downloaded libcpex_ffi.a:
( cd cmd/authbridge-cpex && \
    ../../scripts/download-ffi.sh && \
    CGO_LDFLAGS="-L./libs -lcpex_ffi" \
        go build -tags cpex -o ./authbridge-cpex . )

# 2. Run a chosen demo. The forward proxy listens on :8080; point
#    your agent / curl at it as the outbound HTTP proxy.
./cmd/authbridge-cpex/authbridge-cpex \
    --config ./demos/cpex/chain-combined.yaml
```

(`scripts/download-ffi.sh` doesn't exist in this PR — it's a future
helper to fetch the pinned `libcpex_ffi.a` from the cpex release
matching `CPEX_FFI_VERSION`. For now build against a local cpex
checkout's `target/release/libcpex_ffi.a`.)

## Scenarios these demos enable

Each scenario is the same shape as the praxis demo's
`scenarios/*.sh`. Run via the agent at `examples/demo/agent/chat.py`
from the cpex-praxis-integration repo.

| Scenario | Persona | Tool | Expected outcome |
|---|---|---|---|
| Engineer ↔ internal repo | alice | `search_repos(visibility=internal)` | 200 OK; `cedar.permit` recorded |
| Engineer ↔ external repo | alice | `search_repos(visibility=external)` | Deny `cpex.cedar_default_deny` |
| HR ↔ compensation (with view_ssn) | bob | `get_compensation` | 200 OK with SSN |
| HR ↔ compensation (no view_ssn) | eve | `get_compensation` | 200 OK; PII scanner records `pii.redacted` |
| Anyone ↔ tool with SSN in args | bob | `send_email(body="SSN: 123-45-6789")` | Deny `cpex.pii_detected` |
| Audit visibility | any | any allowed call | Audit-log entry visible in the `slog` stream with `req_id` correlation |

## Caveats (PR 1 limitations)

- **Body modifications aren't yet applied** — the PII scanner's
  `redact` outcome records a `modify` Invocation and produces a
  warning in the slog stream, but `pctx.Body` reaches the upstream
  MCP server unchanged. Format-aware re-serialization is on the
  roadmap; until it lands, prefer the `deny` outcome
  (e.g. APL `pii.detected: deny`) for guardrails that need to gate
  traffic.
- **Per-sub-plugin Invocations** are aggregated into a single
  Invocation per CPEX call. A CPEX FFI change to expose
  per-sub-plugin outcomes will let abctl render the chain inline.
