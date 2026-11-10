#!/usr/bin/env bash
# An insider flips a recorded deny to an allow in the log on disk.
source "$(dirname "$0")/_lib.sh"
title "05  An insider rewrites the record"
say "an insider edits the log: Alice's refused request now reads Allowed"
"$SCENARIO_DIR/../run.sh" tamper >/dev/null
say "the gateway restarts on the edited log"
ok "the edit is caught: the signature breaks, and the ledger holds the original"
