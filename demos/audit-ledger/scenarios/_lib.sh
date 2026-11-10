# shellcheck shell=bash
# Shared helpers for the scenarios.
set -euo pipefail
SCENARIO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../env.sh
source "$SCENARIO_DIR/../env.sh"

BOLD="\033[1m"; DIM="\033[2m"; RED="\033[1;31m"; GREEN="\033[1;32m"; YELLOW="\033[1;33m"; RESET="\033[0m"

# PRESENTER=1 (the recording) keeps only the agent's actions and one-line outcomes: the
# caption bar carries the story, and the audit pane above carries the evidence.
presenter() { [ "${PRESENTER:-0}" = 1 ]; }
title() { presenter || { echo; echo -e "${BOLD}━━━ $1 ━━━${RESET}"; }; }
ok() { echo -e "  ${GREEN}✓${RESET} $1"; }
fail() { echo -e "  ${RED}✗${RESET} $1"; exit 1; }
# say <line>: a narrated step, shown in both modes.
say() { echo -e "  ${YELLOW}▸${RESET} $1"; }
# business <who> <policy>: what the scenario is about, in one line each.
business() { presenter || { echo -e "  ${YELLOW}Who${RESET}     $1"; echo -e "  ${YELLOW}Policy${RESET}  $2"; }; }

agent() { python3 "$SCENARIO_DIR/../agent/agent.py" "$@"; }

# mark: how many records the sink has written. since <mark>: those written after it.
records() { [ -f "$RECORDS" ] && grep '^{' "$RECORDS" || true; }
mark() { records | wc -l | tr -d ' '; }
since() { records | tail -n +"$(($1 + 1))"; }

# wait_records <mark> <n>: the sink writes off the request path, so give it a moment.
wait_records() {
  for _ in $(seq 1 50); do [ "$(($(mark) - $1))" -ge "$2" ] && return 0; sleep 0.1; done
  fail "expected $2 new record(s) after the call, found $(($(mark) - $1))"
}

# show_records <mark>: one line per record the calls produced.
show_records() {
  presenter && return 0
  echo -e "  ${DIM}records the gateway wrote:${RESET}"
  since "$1" | jq -r '"    seq \(.unmapped."aid.stream".stream_seq)  \(.tool.name // "-")  \(.action)" +
      (if .status_code then "  \(.status_code)" else "" end)'
}
