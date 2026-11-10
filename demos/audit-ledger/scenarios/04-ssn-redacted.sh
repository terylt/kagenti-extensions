#!/usr/bin/env bash
# Eve, HR without SSN access, asks for the SSN and gets it redacted in flight.
source "$(dirname "$0")/_lib.sh"
title "04  SSN redacted in flight: the record proves it without holding it"
business "Eve, HR generalist (no view_ssn)" "result.ssn is redacted unless the caller holds perm.view_ssn"
M=$(mark)
out=$(AGENT_JSON=1 agent --user eve --session eve-hr-copilot call get_compensation '{"employee_id":"EMP-001234","include_ssn":true}')
echo "$out" | sed '$d'
ssn=$(echo "$out" | tail -1 | jq -r '.payload.ssn')
[ "$ssn" != "123-45-6789" ] || fail "eve received the SSN"
ok "the ssn field eve received: $ssn"
wait_records "$M" 1
show_records "$M"
if since "$M" | grep -q '123-45-6789'; then fail "the SSN is in the audit record"; fi
ok "the SSN appears nowhere in the audit trail"
