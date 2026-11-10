#!/usr/bin/env bash
# The audit-ledger demo: every policy verdict cortex makes becomes a signed,
# chained OCSF record, receipted by an independent ledger and verified in
# agentop's audit pane.
#
#   ./run.sh up          start the ledger, the HR server, cortex and the shipper
#   ./run.sh observe     open agentop on this demo (audit pane: press V)
#   ./run.sh scenarios   run the four HR scenarios (needs `up`)
#   ./run.sh walkthrough the whole story in order, scenes 01-07 (see demo/steps.md)
#   ./run.sh reset       empty the records and the ledger, keeping keys and tokens
#   ./run.sh tamper      flip a recorded deny to an allow on disk, restart cortex
#   ./run.sh delete      delete a recorded deny on disk, restart cortex
#   ./run.sh restart     kill -9 cortex and start it again (a new epoch)
#   ./run.sh status
#   ./run.sh down        stop everything `up` started; --purge also deletes .state/
#
# Listeners use loopback ports 478xx, cortex and agentop run with HOME under
# .state/, and ~/.cortex and an installed cortex service are left alone.
# CORTEX_BIN picks the cortex binary; it must be a cpex build with the audit
# sink (`make cortex-cpex CPEX_FFI_DIR=<dir> CORTEX_CPEX_TAGS=cortexaudit`).
# AGENTOP_BIN picks agentop; otherwise one is built into .state/bin.

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$DIR/../.." && pwd)"
# shellcheck source=env.sh
source "$DIR/env.sh"

PIDS="$STATE_DIR/pids"
LOGS="$STATE_DIR/logs"

die() { echo "run.sh: $*" >&2; exit 1; }
info() { echo "  ▸ $*"; }

# --- prerequisites ---------------------------------------------------------

# Not grep -q: it stops at the first match, nm then dies of SIGPIPE, and pipefail fails the check.
has_audit_sink() { nm "$1" 2>/dev/null | grep cortex_audit_register_factories >/dev/null; }

find_cortex() {
  local c="${CORTEX_BIN:-$REPO/bin/cortex-cpex/cortex}"
  [ -x "$c" ] || die "no cortex at $c. Build one: make cortex-cpex CPEX_FFI_DIR=<dir with the audit libcpex_ffi.a> CORTEX_CPEX_TAGS=cortexaudit"
  "$c" --version 2>/dev/null | grep -q '^cortex (cpex) ' || die "$c is not a cpex build of cortex"
  has_audit_sink "$c" || die "$c has no audit sink; rebuild with CORTEX_CPEX_TAGS=cortexaudit"
  echo "$c"
}

find_agentop() {
  if [ -n "${AGENTOP_BIN:-}" ]; then echo "$AGENTOP_BIN"; return; fi
  local a="$STATE_DIR/bin/agentop"
  if [ ! -x "$a" ]; then
    mkdir -p "$STATE_DIR/bin"
    info "building agentop into .state/bin (once)" >&2
    (cd "$REPO/cmd/agentop" && go build -o "$a" .) >&2
  fi
  echo "$a"
}

check_tools() {
  local t
  for t in python3 openssl curl jq lsof docker git nm; do
    command -v "$t" >/dev/null || die "$t is required"
  done
}

# --- processes -------------------------------------------------------------

pid_of() { cat "$PIDS/$1.pid" 2>/dev/null || true; }
alive() { local p; p="$(pid_of "$1")"; [ -n "$p" ] && kill -0 "$p" 2>/dev/null; }
listener() { lsof -nP -iTCP:"$1" -sTCP:LISTEN -t 2>/dev/null | head -1 || true; }

check_ports() {
  local p pid ours=" "
  for n in cortex hr; do alive "$n" && ours+="$(pid_of "$n") "; done
  for p in $CORTEX_PORTS $HR_PORT; do
    pid="$(listener "$p")"
    if [ -n "$pid" ] && [[ "$ours" != *" $pid "* ]]; then
      die "port $p is held by pid $pid ($(ps -o comm= -p "$pid" 2>/dev/null)), which this demo did not start"
    fi
  done
}

start() {
  local name="$1"; shift
  if alive "$name"; then info "$name already running (pid $(pid_of "$name"))"; return; fi
  nohup "$@" >>"$LOGS/$name.log" 2>&1 &
  echo $! >"$PIDS/$name.pid"
  info "$name started (pid $!, log .state/logs/$name.log)"
}

stop() {
  local name="$1" signal="${2:-TERM}" pid
  pid="$(pid_of "$name")"
  if alive "$name"; then
    kill "-$signal" "$pid" 2>/dev/null || true
    for _ in $(seq 1 50); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
    info "stopped $name (pid $pid, SIG$signal)"
  fi
  rm -f "$PIDS/$name.pid"
}

wait_for() {
  local what="$1" url="$2"
  for _ in $(seq 1 120); do
    curl -fsS --max-time 2 -o /dev/null "$url" 2>/dev/null && return 0
    sleep 0.5
  done
  die "$what did not come up at $url; see .state/logs/"
}

compose() {
  LEDGER_DIR="$LEDGER_DIR" LEDGER_IMAGE="$LEDGER_IMAGE" LEDGER_PG_PORT="$LEDGER_PG_PORT" \
    LEDGER_GRPC_PORT="$LEDGER_GRPC_PORT" LEDGER_HEALTH_PORT="$LEDGER_HEALTH_PORT" \
    docker compose -f "$DIR/docker-compose.yml" "$@"
}

service_pid() { listener 47600; }

# --- generated material ----------------------------------------------------

b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

# mint <user> <roles json> <permissions json>: a token the policy's jwt-user verifies.
mint() {
  local now hdr payload sig
  now="$(date +%s)"
  hdr="$(printf '{"alg":"RS256","typ":"JWT"}' | b64url)"
  payload="$(jq -cn --arg u "$1" --argjson r "$2" --argjson p "$3" --argjson now "$now" \
    '{iss: "https://idp.audit-demo.invalid", aud: "cortex-audit-demo", sub: $u,
      preferred_username: $u, roles: $r, permissions: $p, iat: $now, exp: ($now + 30*86400)}' | b64url)"
  sig="$(printf '%s.%s' "$hdr" "$payload" | openssl dgst -sha256 -sign "$IDENTITY_DIR/idp.key" | b64url)"
  (umask 077; printf '%s.%s.%s' "$hdr" "$payload" "$sig" >"$IDENTITY_DIR/$1.jwt")
}

gen_identity() {
  [ -f "$IDENTITY_DIR/bob.jwt" ] && return
  mkdir -p "$IDENTITY_DIR" && chmod 700 "$IDENTITY_DIR"
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$IDENTITY_DIR/idp.key" 2>/dev/null
  chmod 600 "$IDENTITY_DIR/idp.key"
  openssl pkey -in "$IDENTITY_DIR/idp.key" -pubout -out "$IDENTITY_DIR/idp.pub.pem"
  mint bob   '["hr"]'       '["tool_execute","email_send","view_ssn"]'
  mint eve   '["hr"]'       '["tool_execute","email_send"]'
  mint alice '["engineer"]' '["tool_execute","email_send"]'
  info "minted tokens for bob (HR), eve (HR, no SSN access) and alice (engineer)"
}

# The gateway's signing key, and its public half where agentop looks for it.
gen_signing_key() {
  local keys="$STATE_DIR/keys"
  [ -f "$keys/ocsf-signing.pem" ] && return
  mkdir -p "$keys" "$CORTEX_DIR/audit/keys" && chmod 700 "$keys"
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$keys/ocsf-signing.pem" 2>/dev/null
  chmod 600 "$keys/ocsf-signing.pem"
  openssl pkey -in "$keys/ocsf-signing.pem" -pubout -out "$CORTEX_DIR/audit/keys/cortex-audit-demo-1.pub.pem"
  info "generated the gateway's P-256 signing key"
}

gen_secrets() {
  [ -f "$STATE_DIR/secrets/provenance.key" ] && return
  mkdir -p "$STATE_DIR/secrets" && chmod 700 "$STATE_DIR/secrets"
  (umask 077; openssl rand -hex 32 >"$STATE_DIR/secrets/provenance.key")
}

render() {
  sed -e "s|@STATE@|$STATE_DIR|g" -e "s|@HOME@|$DEMO_HOME|g" "$1" >"$2"
}

fetch_ledger() {
  if [ "$(git -C "$LEDGER_DIR" rev-parse HEAD 2>/dev/null || true)" != "$LEDGER_COMMIT" ]; then
    rm -rf "$LEDGER_DIR"
    git init -q "$LEDGER_DIR"
    git -C "$LEDGER_DIR" remote add origin "$LEDGER_REPO"
    git -C "$LEDGER_DIR" fetch -q --depth 1 origin "$LEDGER_COMMIT"
    git -C "$LEDGER_DIR" checkout -q FETCH_HEAD
    info "checked out the ledger at ${LEDGER_COMMIT:0:7} (migrations, CPEX adapter)"
  fi
}

python_env() {
  [ -x "$STATE_DIR/venv/bin/python" ] && return
  python3 -m venv "$STATE_DIR/venv"
  "$STATE_DIR/venv/bin/pip" install -q -r "$LEDGER_DIR/adapters/cpex/requirements.txt"
  info "installed the ledger adapter's Python dependencies into .state/venv"
}

prepare_state() {
  mkdir -p "$STATE_DIR" "$PIDS" "$LOGS" "$CORTEX_DIR/audit"
  chmod 700 "$STATE_DIR" "$DEMO_HOME"
  gen_identity
  gen_signing_key
  gen_secrets
  render "$DIR/config/cortex.yaml" "$CORTEX_DIR/config.yaml"
  render "$DIR/config/cpex-policy.yaml" "$STATE_DIR/cpex-policy.yaml"
  fetch_ledger
  python_env
}

start_cortex() {
  (cd "$STATE_DIR" && HOME="$DEMO_HOME" start cortex "$CORTEX" --config "$CORTEX_DIR/config.yaml")
  wait_for "cortex" "$HEALTH_URL/readyz"
}

# --- commands --------------------------------------------------------------

up() {
  local before
  check_tools
  CORTEX="$(find_cortex)"
  before="$(service_pid)"
  check_ports
  prepare_state
  info "cortex: $CORTEX ($("$CORTEX" --version))"

  compose up -d --quiet-pull >/dev/null 2>&1 || compose up -d
  wait_for "the ledger" "http://127.0.0.1:$LEDGER_HEALTH_PORT/readyz"
  info "ledger ready on $LEDGER_ADDR"
  start hr python3 "$DIR/hr/server.py" --port "$HR_PORT"
  wait_for "the HR server" "http://127.0.0.1:$HR_PORT/healthz"
  start_cortex
  curl -fsS "$SESSION_API/v1/audit?limit=1" >/dev/null || die "cortex is up but does not serve /v1/audit"
  start shipper "$STATE_DIR/venv/bin/python" -u "$DIR/shipper/ship.py" --file "$RECORDS" \
    --endpoint "$LEDGER_ADDR" --adapter "$LEDGER_DIR/adapters/cpex"
  info "ready: proxy $DEMO_PROXY, session API $SESSION_API, records $RECORDS"
  [ "$(service_pid)" = "$before" ] || die "the process on :47600 changed while starting the demo"
  [ -z "$before" ] || info "installed cortex service on :47600 (pid $before) untouched"
  echo
  echo "  Next: ./run.sh observe   (in a second terminal; press V for the audit pane)"
  echo "        ./run.sh scenarios"
}

observe() {
  local agentop
  agentop="$(find_agentop)"
  exec env HOME="$DEMO_HOME" "$agentop" observe --endpoint "$SESSION_API" --ledger "$LEDGER_ADDR" "$@"
}

scenarios() {
  local s passed=() failed=()
  alive cortex || die "the demo is not up; run ./run.sh up"
  for s in "$DIR"/scenarios/0[1-4]-*.sh; do
    if bash "$s"; then passed+=("$(basename "$s")"); else failed+=("$(basename "$s")"); fi
  done
  echo
  for s in ${passed[@]+"${passed[@]}"}; do printf '  \033[1;32m✓\033[0m %s\n' "$s"; done
  for s in ${failed[@]+"${failed[@]}"}; do printf '  \033[1;31m✗\033[0m %s\n' "$s"; done
  echo "  ${#passed[@]} passed, ${#failed[@]} failed"
  [ "${#failed[@]}" -eq 0 ]
}

# edit_records <tamper|delete>: change the records file in place, as an insider with write
# access to it would. In place (same file, rewritten) so the shipper does not mistake it for a
# rotation. Cortex is stopped first and started after, so its store re-reads what is on disk.
edit_records() {
  local what="$1"
  alive cortex || die "the demo is not up; run ./run.sh up"
  [ -s "$RECORDS" ] || die "no records yet; run ./run.sh scenarios first"
  CORTEX="$(find_cortex)"
  stop cortex TERM
  python3 "$DIR/tools/edit_records.py" "$what" "$RECORDS"
  start_cortex
  info "cortex restarted on the edited file; agentop's audit pane refetches on reconnect"
}

restart() {
  alive cortex || die "the demo is not up; run ./run.sh up"
  CORTEX="$(find_cortex)"
  stop cortex KILL
  start_cortex
  info "cortex restarted: a new epoch, with stream_seq back at 0"
}

# reset: an empty audit pane and an empty ledger, for a fresh take. Keys, tokens and the
# Python environment stay, so this takes seconds rather than a reinstall.
reset() {
  alive cortex || die "the demo is not up; run ./run.sh up"
  CORTEX="$(find_cortex)"
  stop shipper TERM
  stop cortex TERM
  compose down -v >/dev/null 2>&1
  rm -f "$RECORDS"
  compose up -d >/dev/null 2>&1
  wait_for "the ledger" "http://127.0.0.1:$LEDGER_HEALTH_PORT/readyz"
  start_cortex
  start shipper "$STATE_DIR/venv/bin/python" -u "$DIR/shipper/ship.py" --file "$RECORDS" \
    --endpoint "$LEDGER_ADDR" --adapter "$LEDGER_DIR/adapters/cpex"
  info "reset: no records, an empty ledger"
}

status() {
  local name
  for name in hr cortex shipper; do
    if alive "$name"; then info "$name running (pid $(pid_of "$name"))"; else info "$name stopped"; fi
  done
  if [ -d "$LEDGER_DIR" ] && [ -n "$(compose ps -q 2>/dev/null)" ]; then info "ledger running ($LEDGER_ADDR)"; else info "ledger stopped"; fi
  [ -f "$RECORDS" ] && info "$(wc -l <"$RECORDS" | tr -d ' ') records in $RECORDS"
  return 0
}

down() {
  local before name
  before="$(service_pid)"
  for name in shipper cortex hr; do stop "$name" TERM; done
  if [ -d "$LEDGER_DIR" ]; then compose down -v >/dev/null 2>&1 && info "stopped the ledger and removed its volume"; fi
  # chmod first: anything Go cached under the demo's HOME is read-only.
  if [ "${1:-}" = "--purge" ]; then chmod -R u+w "$STATE_DIR" 2>/dev/null; rm -rf "$STATE_DIR" && info "removed .state/"; fi
  [ "$(service_pid)" = "$before" ] || die "the process on :47600 changed while stopping the demo"
}

case "${1:-}" in
  up) up ;;
  observe) observe "${@:2}" ;;
  scenarios) scenarios ;;
  tamper) edit_records tamper ;;
  delete) edit_records delete ;;
  restart) restart ;;
  reset) reset ;;
  walkthrough) alive cortex || die "the demo is not up; run ./run.sh up"; "$DIR/demo/walkthrough.sh" "${@:2}" ;;
  status) status ;;
  down) down "${2:-}" ;;
  *) sed -n '2,21p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
