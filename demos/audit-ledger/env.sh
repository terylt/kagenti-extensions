# shellcheck shell=bash disable=SC2034
# Addresses and paths shared by run.sh, the agent and the scenarios.
#
# Everything listens on loopback ports 4780x-4782x, apart from an installed
# cortex service on 4760x and the coding-agent demo on 4770x. Cortex and
# agentop run with HOME under .state/, so ~/.cortex is never read or written.
DEMO_DIR="${DEMO_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
STATE_DIR="$DEMO_DIR/.state"
DEMO_HOME="$STATE_DIR/home"
CORTEX_DIR="$DEMO_HOME/.cortex"

CORTEX_PORTS="47800 47801 47802 47803"
HR_PORT=47810
LEDGER_GRPC_PORT=47820
LEDGER_HEALTH_PORT=47821
LEDGER_PG_PORT=47822

# The ARE ledger at v0.2.0: the image the compose file runs, and the checkout
# its migrations and CPEX adapter come from. Move both together.
LEDGER_REPO="https://github.com/jkershawrh/are-immutable-ledger.git"
LEDGER_COMMIT="544528f23cafce547c032936e07df23f9d41d677"
LEDGER_IMAGE="ghcr.io/jkershawrh/are-immutable-ledger:0.2.0"
LEDGER_DIR="$STATE_DIR/ledger"

export DEMO_DIR DEMO_STATE="$STATE_DIR" DEMO_HOME
export DEMO_PROXY="http://127.0.0.1:47800"
export SESSION_API="http://127.0.0.1:47801"
export HEALTH_URL="http://127.0.0.1:47803"
# localtest.me resolves to 127.0.0.1, and a name rather than a loopback
# address keeps the call on the proxy rather than in a no-proxy list.
export HR_URL="http://hr.localtest.me:$HR_PORT"
export LEDGER_ADDR="127.0.0.1:$LEDGER_GRPC_PORT"
export RECORDS="$CORTEX_DIR/audit/records.ndjson"
export IDENTITY_DIR="$STATE_DIR/identity"
