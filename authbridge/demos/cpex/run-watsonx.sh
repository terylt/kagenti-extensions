#!/usr/bin/env bash
# One-shot launcher for the kagenti CPEX demo chat agent backed by IBM
# watsonx.ai (Meta Llama models).
#
# Walks through:
#   1. Required env-var check (WATSONX_APIKEY / WATSONX_URL /
#      WATSONX_PROJECT_ID) — sourced from `.env` in this directory
#      when present
#   2. Sanity ping against the kagenti-deployed gateway (:8082) and
#      Keycloak (:8081) — both reached via `kubectl port-forward`
#   3. Persona selection (defaults to bob — the "HR happy path")
#   4. Model selection (defaults to llama-3-3-70b-instruct — needed
#      for reliable tool-calling; smaller Llamas often skip tool use)
#   5. Launches the bundled chat.py with the chosen persona +
#      model + kagenti gateway URL
#
# Prerequisites:
#   • `make deploy` from this directory completed successfully
#   • `make port-forward` running in another terminal (exposes :8081
#     for Keycloak and :8082 for the gateway)
#   • Python venv in ./agent/ with requirements.txt installed
#
# Usage:
#
#     export WATSONX_APIKEY=...           # IBM Cloud API key
#     export WATSONX_URL=https://us-south.ml.cloud.ibm.com
#     export WATSONX_PROJECT_ID=...       # watsonx.ai project ID
#
#     ./run-watsonx.sh                    # bob + 70B Llama
#     ./run-watsonx.sh alice              # try the deny scenario
#     ./run-watsonx.sh eve                # try the REDACT scenario ★
#     ./run-watsonx.sh bob meta-llama/llama-3-1-8b-instruct
#                                         # override the model
#
# Suggested demo flow once the chat is up:
#
#     Bob: "look up compensation for EMP-001234, include the SSN"
#     → 200 OK, SSN visible
#
#     > switch eve
#     Eve: "look up compensation for EMP-001234, include the SSN"
#     → 200 OK, SSN REDACTED from the response body
#     ★ THE WOW. Same backend. Same request. Different data because policy.
#
#     > switch alice
#     Alice: "look up compensation"
#     → JSON-RPC error -32001, Alice isn't HR

set -euo pipefail

# Paths — derived once so reorganising the demo dir doesn't break
# the script. AGENT_DIR holds the bundled chat.py + requirements.txt.
DEMO_DIR="$(cd "$(dirname "$0")" && pwd)"
AGENT_DIR="$DEMO_DIR/agent"

PERSONA="${1:-bob}"
# Llama 3.3 70B handles tool-use reliably; 8B can ignore tools in
# longer conversations.
MODEL="${2:-watsonx/meta-llama/llama-3-3-70b-instruct}"

# Source .env from this directory if present — lets operators keep
# WATSONX_* values out of their shell rc files.
if [ -f "$DEMO_DIR/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  source "$DEMO_DIR/.env"
  set +a
fi

# Kagenti deploy port-forward targets. Override if you've forwarded
# the services to different ports.
GATEWAY_URL="${GATEWAY_URL:-http://localhost:8082/mcp}"
KEYCLOAK_HOST="${KEYCLOAK_HOST:-http://localhost:8081}"
KEYCLOAK_REALM="${KEYCLOAK_REALM:-cpex-demo}"

red()   { printf '\033[31m%s\033[0m' "$*"; }
green() { printf '\033[32m%s\033[0m' "$*"; }
dim()   { printf '\033[2m%s\033[0m' "$*"; }

die()   { echo "  $(red ✗) $*" >&2; exit 1; }
ok()    { echo "  $(green ✓) $*"; }
info()  { echo "  $(dim ▸) $*"; }

# 1. Env vars
echo "Checking watsonx env…"
[ -n "${WATSONX_APIKEY:-}" ]     || die "WATSONX_APIKEY not set (export or put in $DEMO_DIR/.env)"
[ -n "${WATSONX_URL:-}" ]        || die "WATSONX_URL not set (e.g. https://us-south.ml.cloud.ibm.com)"
[ -n "${WATSONX_PROJECT_ID:-}" ] || die "WATSONX_PROJECT_ID not set"
ok "WATSONX_APIKEY     [set]"
ok "WATSONX_URL        $WATSONX_URL"
ok "WATSONX_PROJECT_ID [set]"

# Normalize model string for litellm.
case "$MODEL" in
  watsonx/*) ;;
  *) MODEL="watsonx/$MODEL" ;;
esac

# 2. Gateway + Keycloak reachability (kagenti deploy via port-forward)
echo
echo "Checking gateway + Keycloak…"
gw_host_port="${GATEWAY_URL#http://}"
gw_host_port="${gw_host_port%%/*}"
gw_host="${gw_host_port%:*}"
gw_port="${gw_host_port##*:}"
if curl -fsS --max-time 3 "http://$gw_host:9091/healthz" >/dev/null 2>&1 \
    || nc -z "$gw_host" "$gw_port" 2>/dev/null; then
  ok "authbridge-cpex gateway @ $GATEWAY_URL"
else
  die "gateway not listening on $GATEWAY_URL — start port-forward from this dir:
       cd $DEMO_DIR && make port-forward"
fi

if curl -fsS --max-time 3 "$KEYCLOAK_HOST/realms/$KEYCLOAK_REALM/.well-known/openid-configuration" >/dev/null 2>&1; then
  ok "Keycloak @ $KEYCLOAK_HOST (realm $KEYCLOAK_REALM)"
else
  die "Keycloak realm $KEYCLOAK_REALM not reachable on $KEYCLOAK_HOST — ensure 'make port-forward' is running"
fi

# 3. Python deps
echo
echo "Checking Python deps…"
[ -f "$AGENT_DIR/chat.py" ] || die "chat.py not found at $AGENT_DIR — directory should ship alongside this script"
if ! python3 -c 'import litellm, httpx, rich' >/dev/null 2>&1; then
  info "installing requirements from $AGENT_DIR/requirements.txt…"
  pip install -q -r "$AGENT_DIR/requirements.txt"
fi
ok "litellm / httpx / rich available"

# 4. Persona
case "$PERSONA" in
  alice|bob|charlie|eve) ok "persona: $PERSONA" ;;
  *) die "unknown persona '$PERSONA'. valid: alice, bob, charlie, eve" ;;
esac

# 5. Launch — env-vared at the kagenti gateway port. Persona / model
# passed as flags.
echo
echo "Launching chat…"
info "model:    $MODEL"
info "persona:  $PERSONA"
info "gateway:  $GATEWAY_URL"
info "keycloak: $KEYCLOAK_HOST"
echo

export GATEWAY_URL
export KEYCLOAK_HOST

exec python3 "$AGENT_DIR/chat.py" --persona "$PERSONA" --model "$MODEL"
