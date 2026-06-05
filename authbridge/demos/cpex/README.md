# CPEX integration demo on kagenti

Runs the full CPEX/APL policy stack as a sidecar in front of an MCP
backend, on a kagenti kind cluster. Three moments for a demo:

1. **Same request, different data based on permission** — Bob (HR with
   `view_ssn`) sees the SSN; Eve (HR without `view_ssn`) gets the same
   call back with the SSN **redacted in the response body**.
2. **Defense in depth** — APL coarse predicate → Cedar PDP → IdP
   token-exchange → PII validator → audit logger, all in one
   declarative YAML.
3. **Policy as data** — the gateway is a generic AuthBridge sidecar;
   all authorization behavior lives in `cpex-policy.yaml`. Operators
   ship policy changes via ConfigMap update, not a code release.

## What this demo assumes is already there

This demo runs **inside** a kagenti environment — it does NOT install
kagenti or build a kind cluster. You need:

- **A kagenti kind cluster** named `kagenti` (override `KIND_CLUSTER`
  in the Makefile if yours is named differently). Install kagenti
  separately following the [kagenti repository instructions][kagenti].
  We use the `kagenti-control-plane` node and create our own
  `cpex-demo` namespace; nothing in the demo touches kagenti's own
  Keycloak / SPIRE / operator state.
- **Docker** for building images locally (loaded into kind, not pushed
  to a registry).
- **kubectl** configured for the `kagenti` cluster context.
- **An `hr-mcp` backend image** built locally. The Makefile expects
  the source at `../../../cpex-mcp-servers/hr-mcp-server/` (override
  with `HR_MCP_SRC=...`); any FastAPI MCP server exposing
  `get_compensation` and `send_email` tools will work as a drop-in.

[kagenti]: https://github.com/kagenti/kagenti

## What the demo creates in your cluster

Everything lives in a fresh `cpex-demo` namespace; `kubectl delete ns
cpex-demo` is a clean tear-down.

| Pod | Image | Purpose |
|---|---|---|
| `keycloak` | `quay.io/keycloak/keycloak:26.0` (public) | OIDC IdP with the `cpex-demo` realm pre-imported from `realm-export.json` |
| `hr-mcp` | `hr-mcp:dev` (built locally) | FastAPI server speaking MCP JSON-RPC with `get_compensation` and `send_email` tools |
| `authbridge-cpex` | `authbridge-cpex:dev` (built locally) | AuthBridge sidecar with the `cpex` plugin enabled; runs the APL policy stack from `cpex-policy.yaml` |

## Bring it up

```bash
# 1. Build images, load into kind, apply manifests, wait for Ready.
make deploy

# 2. In another terminal: forward Keycloak (:8081) + gateway (:8082).
make port-forward

# 3. Run the seven curl scenarios.
make scenarios
```

Expected `make scenarios` output: all seven scenarios produce HTTP 200
+ a JSON-RPC result or a deny. The interesting ones to call out:

```
01-bob-allow.sh                          PASS (SSN visible)
02-alice-deny.sh                         DENY  (cpex.denied — APL: require(role.hr))
03-eve-redact.sh                         PASS (SSN REDACTED in response)   ← WOW
04-alice-internal-allow.sh               PASS  (Cedar permit + token exchange)
05-alice-external-cedar-deny.sh          DENY  (cpex.cedar_default_deny)
06-bob-apl-deny.sh                       DENY  (APL: team mismatch)
07-bob-pii-deny.sh                       DENY  (cpex.pii_detected)
```

## Interactive chat (the real demo)

The scenario scripts above are deterministic curl runs. For an
audience demo, drive it with an LLM agent that switches personas
mid-conversation:

```bash
cd agent
# First time only: create venv + install deps.
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Then either use the one-shot launcher (watsonx-flavored, does
preflight + persona/model selection):

```bash
cd ..                            # back to demos/cpex/
# Put your watsonx creds in .env (gitignored) once:
cat > .env <<'EOF'
WATSONX_APIKEY=your-key
WATSONX_URL=https://us-south.ml.cloud.ibm.com
WATSONX_PROJECT_ID=your-project-id
EOF
chmod 600 .env

./run-watsonx.sh                 # bob (HR happy path)
./run-watsonx.sh eve             # ★ the REDACT scenario
./run-watsonx.sh alice           # deny scenarios
```

Or run `chat.py` directly with any LLM litellm supports:

```bash
cd agent
KEYCLOAK_HOST=http://localhost:8081 \
GATEWAY_URL=http://localhost:8082/mcp \
python chat.py --persona bob --model gpt-4o-mini
```

In-chat commands:

```
switch alice      # swap persona (re-mints both tokens)
relogin           # refresh both tokens (use if they expire mid-demo)
quit
```

See `agent/CHAT-WALKTHROUGH.md` for a longer suggested conversation
script and discussion talking-points.

Conversation script for the demo:

```
You: look up the compensation for EMP-001234, include the SSN
  → 200 OK, SSN included in response

You: switch eve
You: look up the compensation for EMP-001234, include the SSN
  → 200 OK, response shows compensation WITHOUT the SSN field
  → ← THIS IS THE WOW. Same backend. Same request. Different data because policy.

You: switch alice
You: look up the compensation for EMP-001234
  → DENY (cpex.denied) — Alice isn't HR

You: search the internal repos for anything called web-app
  → 200 OK — Cedar permits (Alice is engineering, repo is internal)

You: search external repos
  → DENY (cpex.cedar_default_deny) — Cedar refuses cross-trust-boundary
```

## How it works end-to-end

```
chat.py (host)
    │
    │ POST /mcp with Authorization (client token) + X-User-Token (persona)
    │
    ▼  port-forward localhost:8082 → svc/authbridge-cpex:8080
┌─────────────────────────────────────────────────────────────────┐
│ authbridge-cpex pod (cpex-demo namespace)                       │
│                                                                 │
│   AuthBridge pipeline:                                          │
│     mcp-parser → cpex                                           │
│                                                                 │
│   cpex plugin's CPEX manager runs cpex-policy.yaml:             │
│                                                                 │
│   ┌────────────────┐ ┌────────────────┐ ┌────────────────────┐  │
│   │ identity/jwt    │ │ pdp/cedar      │ │ delegator/oauth    │  │
│   │   jwt-user      │ │   role+resource│ │   workday-oauth    │──┼──► Keycloak
│   │   jwt-client    │ │   decisions    │ │   github-oauth     │  │   svc:8080
│   └────────────────┘ └────────────────┘ └────────────────────┘  │
│                                                                 │
│   ┌────────────────┐ ┌────────────────┐                          │
│   │ validator/pii  │ │ audit/logger   │                          │
│   └────────────────┘ └────────────────┘                          │
│                                                                 │
│   On allow: reverse-proxy → hr-mcp:9100 (in cluster)             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                                              │
                                              ▼ in-cluster
                                       svc/hr-mcp:9100 (Pod)
```

## Configuration files

| File | What it does |
|---|---|
| `k8s/00-namespace.yaml` | Creates `cpex-demo` namespace |
| `k8s/10-keycloak.yaml` | Keycloak Service + Deployment (realm-import via ConfigMap built by Makefile) |
| `k8s/20-hr-mcp.yaml` | hr-mcp backend Service + Deployment |
| `k8s/30-authbridge-cpex.yaml` | AuthBridge config ConfigMap + Service + Deployment |
| `k8s/realm-export.json` | Keycloak realm definition (users, clients, mappers) |
| `k8s/cpex-policy.yaml` | CPEX runtime YAML — APL identity + PDP + delegator + validators + audit |

The AuthBridge config (inline in `30-authbridge-cpex.yaml`) is short
and operator-readable. The CPEX policy YAML (`cpex-policy.yaml`) is
the heavier file — that's where the actual policy lives.

## Editing policy and re-applying

The cpex-policy ConfigMap is recreated from `k8s/cpex-policy.yaml` on
every `make apply`, so the YAML file is the source of truth. After
editing:

```bash
make apply
kubectl -n cpex-demo rollout restart deployment/authbridge-cpex
```

(`make apply` regenerates the ConfigMap but doesn't restart the pod
since the Deployment spec didn't change. The rollout-restart forces a
fresh pod that picks up the new ConfigMap.)

## Tear down

```bash
make undeploy   # deletes the cpex-demo namespace; clean exit
```

This leaves the kagenti cluster, its system namespaces, and other
demos intact.

## Known gotchas

- **Keycloak `iss` claim** is set via `KC_HOSTNAME` to
  `http://keycloak.cpex-demo:8080`. Tokens minted via the
  port-forwarded localhost:8081 still carry that cluster-internal iss
  — the in-cluster gateway then verifies it as expected.
  `KC_HOSTNAME_STRICT=false` lets clients reach Keycloak at any
  hostname they like (port-forward, in-cluster DNS, etc.).
- **`insecure_http: true`** is set on every plugin that talks to
  Keycloak over HTTP (jwt-user, jwt-client, workday-oauth,
  github-oauth) because our P0-3/P0-4 validator rejects plaintext
  JWKS / token-endpoint URLs by default. Production deployments
  should put TLS in front of Keycloak and remove these flags.
- **Image rebuilds** require `kubectl rollout restart
  deployment/authbridge-cpex` after `kind load docker-image
  authbridge-cpex:dev` — the Deployment spec is identical so a plain
  `apply` doesn't trigger a fresh pod.
## What this demo doesn't yet cover

- **Kagenti UI integration** — pods deploy via plain `kubectl apply`,
  not via the kagenti operator-injection pattern. Promoting cpex into
  the operator's recognised sidecar list is a separate
  kagenti-extensions change.
- **abctl TUI** — would render the per-Invocation chain visually,
  including the deny short-circuit. Needs the per-sub-plugin
  Invocation work (PR-2 follow-up) to land first.
- **Production-grade TLS** — Keycloak runs on plaintext HTTP. Wire a
  cert via cert-manager and flip the insecure_http flags off for any
  real deployment.
