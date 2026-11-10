#!/usr/bin/env bash
# Alice, an engineer, tries the same. Denied before the HR system sees it.
source "$(dirname "$0")/_lib.sh"
title "02  Engineer reads compensation: denied at the gateway"
business "Alice, principal engineer" "require(role.hr) on get_compensation"
M=$(mark)
if agent --user alice --session alice-copilot call get_compensation '{"employee_id":"EMP-001234"}'; then
  fail "alice was allowed"
fi
wait_records "$M" 1
show_records "$M"
since "$M" | jq -e 'select(.action == "Denied")' >/dev/null || fail "no deny record"
ok "refused, and on the record with the rule that said no"
