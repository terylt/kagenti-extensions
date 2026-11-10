#!/usr/bin/env bash
# The gateway crashes and restarts; then the day goes on.
source "$(dirname "$0")/_lib.sh"
title "07  The gateway crashes"
say "the gateway crashes and restarts"
"$SCENARIO_DIR/../run.sh" restart >/dev/null
agent --user bob --session bob-hr-copilot call get_compensation '{"employee_id":"EMP-005678"}' >/dev/null ||
  fail "bob was denied after the restart"
ok "a new epoch begins, marked in the record: a crash, not a gap"
