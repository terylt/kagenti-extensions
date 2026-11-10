#!/usr/bin/env bash
# The insider deletes a recorded deny instead.
source "$(dirname "$0")/_lib.sh"
title "06  An insider deletes a record"
say "the insider deletes the record of the blocked email instead"
"$SCENARIO_DIR/../run.sh" delete >/dev/null
ok "the gap shows, and the ledger kept the deleted record"
