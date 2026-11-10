#!/usr/bin/env bash
# Bob, HR, reads a salary through the agent. Allowed, and on the record.
source "$(dirname "$0")/_lib.sh"
title "01  HR reads compensation: allowed, with evidence"
business "Bob, HR business partner" "only the hr role may read compensation"
M=$(mark)
agent --user bob --session bob-hr-copilot call get_compensation '{"employee_id":"EMP-001234"}' || fail "bob was denied"
wait_records "$M" 1
show_records "$M"
# Modified, not Allowed: the route taints the session, which is an allow that changed state.
since "$M" | jq -e 'select((.action == "Allowed" or .action == "Modified") and .tool.name == "get_compensation")' >/dev/null ||
  fail "no allow record for get_compensation"
ok "allowed and on the record, with a receipt from the independent ledger"
