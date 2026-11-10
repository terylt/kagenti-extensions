#!/usr/bin/env bash
# The whole story, scenes in demo/steps.md order.
#
#   demo/walkthrough.sh               pause for Enter between scenes (q quits)
#   demo/walkthrough.sh --pace 3      advance by itself: the caption shows 3s before a scene
#   demo/walkthrough.sh --hold 5      seconds a scene's outcome stays up (default 5; with --pace)
#   demo/walkthrough.sh --presenter   condensed output, for a recording (also PRESENTER=1)
#
# Assumes ./run.sh up. When WALKTHROUGH_HOOK is set it is run as
# `$WALKTHROUGH_HOOK scenario <name>` before each scene (`title` first,
# `summary` last), as `$WALKTHROUGH_HOOK refresh` after a scene that restarted
# cortex, so the recorder can bring agentop up to date, and as
# `$WALKTHROUGH_HOOK inspect tamper|gap` after the tamper and the deletion, so
# it can open the record and show what changed or what was deleted. The
# inspect hook returns when it is done.

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEMO_DIR="$(cd "$DIR/.." && pwd)"
PACE=0
HOLD=5
while [ $# -gt 0 ]; do
  case "$1" in
    --pace) PACE="${2:?--pace needs seconds}"; shift ;;
    --hold) HOLD="${2:?--hold needs seconds}"; shift ;;
    --presenter) export PRESENTER=1 ;;
    -h|--help) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

hook() { [ -z "${WALKTHROUGH_HOOK:-}" ] || "$WALKTHROUGH_HOOK" "$@"; }

# The scenes, in the order steps.md's table lists them.
scenes() { grep -oE '^\| [0-9]+ \|[^|]*\| `[^`]+`' "$DIR/steps.md" | grep -oE '`[^`]+`' | tr -d '`'; }

pause() {
  if [ "$PACE" != 0 ]; then sleep "$1"; return; fi
  local key
  read -r -n 1 -s -p "  [Enter] next   [q] quit" key </dev/tty || true
  printf '\r\033[K'
  [ "$key" = q ] && exit 0
  return 0
}

hook scenario title
[ "$PACE" != 0 ] && sleep "$PACE"
failed=0
for s in $(scenes); do
  name="${s%.sh}"
  hook scenario "$name"
  [ "$PACE" != 0 ] && sleep "$PACE"
  bash "$DEMO_DIR/scenarios/$s" || failed=1
  case "$name" in 05-*|06-*|07-*) hook refresh ;; esac
  case "$name" in
    05-*) hook inspect tamper ;;
    06-*) hook inspect gap ;;
  esac
  pause "$HOLD"
done
hook scenario summary
[ "$PACE" != 0 ] && sleep "$HOLD"
exit "$failed"
