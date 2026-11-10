#!/usr/bin/env bash
# Record the walkthrough as a video: the caption bar on top, agentop's audit
# pane filling the middle, the agent's actions below.
#
#   demo/record.sh [--pace N] [--hold N] [--out PATH]
#   demo/record.sh --check     the scenario scripts and demo/steps.md agree
#
#   --pace N   seconds a caption shows before its scene runs (default 4)
#   --hold N   seconds a scene's outcome stays up before the next (default 7)
#   --out PATH default demo/out/audit-ledger
#
# Writes PATH.cast (asciinema), PATH.gif (agg) and PATH.mp4 (ffmpeg). Needs
# ./run.sh up, tmux, asciinema 3, agg and ffmpeg. Resets the demo first, so
# the video starts from an empty audit pane and an empty ledger. agentop runs
# with the demo's HOME; tmux uses its own socket.
#
# The walkthrough calls this script as its WALKTHROUGH_HOOK:
#   demo/record.sh scenario <name>   the caption bar and the policy slide switch to that scene
#   demo/record.sh verdict <kind>    the agent's call returned allow or deny; the slide lights
#   demo/record.sh refresh           cortex restarted; agentop refetches
#   demo/record.sh inspect tamper    hold on the list, open the tampered record, hold, return
#   demo/record.sh inspect gap       the same for the deleted record, read back from the ledger

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEMO_DIR="$(cd "$HERE/.." && pwd)"
REPO="$(cd "$DEMO_DIR/../.." && pwd)"
# shellcheck source=../env.sh
source "$DEMO_DIR/env.sh"

SOCK=audit-ledger-demo
NAME=audit-ledger-demo
REC="$STATE_DIR/record"
COLS=160
ROWS=47

die() { echo "record.sh: $*" >&2; exit 1; }
tm() { tmux -L "$SOCK" "$@"; }

# --- agentop driver --------------------------------------------------------------

# The pane id, saved once the layout exists, so the hook processes the walkthrough starts can
# reach agentop too.
AGENTOP_PANE="$(cat "$REC/agentop_pane" 2>/dev/null || true)"
# Seconds on the list with the evidence visible before the record opens, and with it open.
LIST_HOLD="${LIST_HOLD:-5}"
INSPECT_HOLD="${INSPECT_HOLD:-8}"
screen() { tm capture-pane -p -t "$AGENTOP_PANE" 2>/dev/null || true; }
on_audit() { screen | head -1 | grep -qF '· audit ·'; }

# open_audit: press V until agentop shows the audit pane.
open_audit() {
  local _
  for _ in $(seq 1 100); do
    on_audit && return 0
    screen | grep -qF agentop && tm send-keys -t "$AGENTOP_PANE" V
    sleep 0.5
  done
  die "agentop never showed the audit pane"
}

# inspect tamper|gap: once agentop shows the evidence, let the list sit so a viewer can read it,
# then jump to it (t for the tampered record, m for the gap), open it, hold, and go back to the
# rows. Blocks, so the walkthrough waits for it.
inspect() {
  local what="${1:-tamper}" mark key _
  case "$what" in
    tamper) mark='was Denied'; key=t ;;
    gap) mark='MISSING'; key=m ;;
    *) die "inspect: unknown target $what" ;;
  esac
  for _ in $(seq 1 60); do
    [ ! -f "$REC/refresh" ] && screen | grep -qF "$mark" && break
    sleep 0.25
  done
  sleep "$LIST_HOLD"
  tm send-keys -t "$AGENTOP_PANE" "$key"
  sleep 0.5
  tm send-keys -t "$AGENTOP_PANE" Enter
  sleep "$INSPECT_HOLD"
  tm send-keys -t "$AGENTOP_PANE" Escape
  sleep 1
}

# drive: open the audit pane with identity checks hidden (the story is the decisions; a flagged
# record shows regardless), release the walkthrough, then bring agentop up to date after each
# restart rather than waiting out its reconnect backoff.
drive() {
  open_audit
  tm send-keys -t "$AGENTOP_PANE" i
  touch "$REC/go"
  while tm has-session -t "$NAME" 2>/dev/null; do
    if [ -f "$REC/refresh" ]; then
      rm -f "$REC/refresh"
      sleep 1.5
      on_audit || open_audit
      tm send-keys -t "$AGENTOP_PANE" r
    fi
    sleep 0.2
  done
}

# --- the hook ------------------------------------------------------------------

case "${1:-}" in
  # Line 1 is the scene, line 2 the latest verdict; renamed into place so a reader never sees
  # half a write.
  scenario) echo "$2" >"$REC/scene.tmp" && mv "$REC/scene.tmp" "$REC/scene"; exit 0 ;;
  verdict) { head -1 "$REC/scene"; echo "$2"; } >"$REC/scene.tmp" && mv "$REC/scene.tmp" "$REC/scene"; exit 0 ;;
  refresh) touch "$REC/refresh"; exit 0 ;;
  inspect) inspect "${2:-tamper}"; exit 0 ;;
  --check) exec python3 "$HERE/caption_bar.py" --check ;;
esac

# --- recording -------------------------------------------------------------------

PACE=4
HOLD=7
OUT="$DEMO_DIR/demo/out/audit-ledger"
while [ $# -gt 0 ]; do
  case "$1" in
    --pace) PACE="${2:?--pace needs seconds}"; shift ;;
    --hold) HOLD="${2:?--hold needs seconds}"; shift ;;
    --out) OUT="${2:?--out needs a path}"; shift ;;
    -h|--help) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
  shift
done

for t in tmux asciinema agg ffmpeg curl python3; do
  command -v "$t" >/dev/null || die "$t is required (brew install tmux asciinema agg ffmpeg)"
done
curl -fsS --max-time 3 "$SESSION_API/v1/audit?limit=1" >/dev/null 2>&1 || die "no demo cortex at $SESSION_API; run ./run.sh up"
tm has-session -t "$NAME" 2>/dev/null && die "a recording is already running (tmux -L $SOCK attach -t $NAME)"
python3 "$HERE/caption_bar.py" --check >/dev/null

AGENTOP="${AGENTOP_BIN:-$STATE_DIR/bin/agentop}"
if [ ! -x "$AGENTOP" ]; then
  mkdir -p "$(dirname "$AGENTOP")"
  echo "  ▸ building agentop into .state/bin (once)"
  (cd "$REPO/cmd/agentop" && go build -o "$AGENTOP" .)
fi

mkdir -p "$REC" "$(dirname "$OUT")"
rm -f "$REC/scene" "$REC/go" "$REC/refresh"
echo title >"$REC/scene"
"$DEMO_DIR/run.sh" reset

q() { printf '%q' "$1"; }
walk="cd $(q "$DEMO_DIR") && while [ ! -f $(q "$REC/go") ]; do sleep 0.2; done; sleep 1; clear; printf %s $(q $'\033[?25l'); \
WALKTHROUGH_HOOK=$(q "$HERE/record.sh") demo/walkthrough.sh --presenter --pace $(q "$PACE") --hold $(q "$HOLD"); \
sleep 1; tmux -L $SOCK kill-session -t $NAME"
agentop="HOME=$(q "$DEMO_HOME") $(q "$AGENTOP") observe --skip-claude-metadata --endpoint $(q "$SESSION_API") --ledger $(q "$LEDGER_ADDR")"
caption="python3 $(q "$HERE/caption_bar.py") --watch $(q "$REC/scene")"
slide="python3 $(q "$HERE/policy_slide.py") --watch $(q "$REC/scene")"

# Layout, top to bottom: captions (4 rows), the audit pane, then the agent with the policy
# slide to its right (15 rows).
tm -f /dev/null new-session -d -s "$NAME" -x "$COLS" -y "$ROWS" "bash -c $(q "$walk")"
tm set -g status off
tm set -g pane-border-status top
tm set -g pane-border-format '#{?pane_title, #{pane_title} ,}'
tm set -g pane-border-style fg=colour240
tm set -g pane-active-border-style fg=colour240
WALK_PANE="$(tm display -p -t "$NAME:0.0" '#{pane_id}')"
CAPTION_PANE="$(tm split-window -P -F '#{pane_id}' -v -b -f -l 4 -t "$WALK_PANE" "$caption")"
AGENTOP_PANE="$(tm split-window -P -F '#{pane_id}' -v -b -l 27 -t "$WALK_PANE" "$agentop")"
SLIDE_PANE="$(tm split-window -P -F '#{pane_id}' -h -l 72 -t "$WALK_PANE" "$slide")"
echo "$AGENTOP_PANE" >"$REC/agentop_pane"
tm select-pane -t "$CAPTION_PANE" -T "" -P 'bg=colour24'
tm select-pane -t "$AGENTOP_PANE" -T "audit trail, checked independently by agentop"
tm select-pane -t "$WALK_PANE" -T "the agent"
tm select-pane -t "$SLIDE_PANE" -T "the policy"
tm select-pane -t "$WALK_PANE"

drive &
DRIVER=$!
trap 'kill "$DRIVER" 2>/dev/null || true; tm kill-session -t "$NAME" 2>/dev/null || true' EXIT

asciinema rec --overwrite --headless --window-size "${COLS}x${ROWS}" --idle-time-limit 8 \
  -c "tmux -L $SOCK attach -t $NAME" "$OUT.cast"

# End on the closing caption, not tmux's exit screen.
python3 - "$OUT.cast" <<'PY'
import json, sys
path = sys.argv[1]
lines = open(path).read().splitlines()
head, events = lines[0], [json.loads(x) for x in lines[1:]]
cut = next((i for i, e in enumerate(events) if e[1] == "o" and "[exited]" in e[2]), len(events))
clear = [i for i, e in enumerate(events[:cut]) if e[1] == "o" and "\x1b[H\x1b[2J" in e[2]]
if clear and cut < len(events):
    cut = clear[-1]
with open(path, "w") as f:
    f.write("\n".join([head] + [json.dumps(e) for e in events[:cut]]) + "\n")
PY
echo "cast: $OUT.cast"
agg -q --font-size 20 --fps-cap 12 --idle-time-limit 8 --last-frame-duration 8 "$OUT.cast" "$OUT.gif"
echo "gif:  $OUT.gif"
ffmpeg -y -loglevel error -i "$OUT.gif" -movflags faststart -pix_fmt yuv420p -r 12 \
  -vf "scale=trunc(iw/2)*2:trunc(ih/2)*2" "$OUT.mp4"
echo "mp4:  $OUT.mp4"
